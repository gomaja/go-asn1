// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s55 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s55

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ResetAcknowledgeIEContainer is ProtocolIE-Container {{ResetAcknowledgeIEs}} of TS 36.413: a list of ResetAcknowledgeIEField values.
type ResetAcknowledgeIEContainer []ResetAcknowledgeIEField

// ResetAcknowledgeIEField is ProtocolIE-Field {{ResetAcknowledgeIEs}} of TS 36.413: an information element field.
type ResetAcknowledgeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ResetAcknowledgeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEField) WithoutReplay() ResetAcknowledgeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ResetAcknowledgeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ResetAcknowledgeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ResetAcknowledgeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResetAcknowledgeIEField{}
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
	var zero ResetAcknowledgeIEValue

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
func BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *ResetAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainer(v *ResetAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainer(v *s41.UplinkNASTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainer(v *s41.UplinkNASTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(v *s14.UplinkNonUEAssociatedLPPaTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(v *s14.UplinkNonUEAssociatedLPPaTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(v *s24.UplinkS1cdma2000tunnellingIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(v *s24.UplinkS1cdma2000tunnellingIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(v *s14.UplinkUEAssociatedLPPaTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(v *s14.UplinkUEAssociatedLPPaTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s25.UserLocationInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s25.UserLocationInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PWSRestartIndicationECGIListForRestartIEBinding binds ECGIListForRestart to the PWSRestartIndicationIEs object set of TS 36.413.
type PWSRestartIndicationECGIListForRestartIEBinding struct {
	info   s00.FieldInfo
	codec  s20.ECGIListForRestartValueCodec
	inject func(s20.ECGIListForRestart,

	) PWSRestartIndicationIEValue

	get func(*PWSRestartIndicationIEValue,

	) (*s20.ECGIListForRestart,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSRestartIndicationECGIListForRestartIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSRestartIndicationECGIListForRestartIEBinding) Codec() s20.ECGIListForRestartValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PWSRestartIndicationECGIListForRestartIEBinding) New(value s20.ECGIListForRestart,

) (PWSRestartIndicationIEField, error) {
	if b.inject == nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeECGIListForRestartValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSRestartIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSRestartIndicationECGIListForRestartIEBinding) Get(field *PWSRestartIndicationIEField) (*s20.ECGIListForRestart,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSRestartIndicationGlobalENBIDIEBinding binds GlobalENBID to the PWSRestartIndicationIEs object set of TS 36.413.
type PWSRestartIndicationGlobalENBIDIEBinding struct {
	info   s00.FieldInfo
	codec  s21.GlobalENBIDValueCodec
	inject func(s21.GlobalENBID,

	) PWSRestartIndicationIEValue

	get func(*PWSRestartIndicationIEValue,

	) (*s21.GlobalENBID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSRestartIndicationGlobalENBIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSRestartIndicationGlobalENBIDIEBinding) Codec() s21.GlobalENBIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PWSRestartIndicationGlobalENBIDIEBinding) New(value s21.GlobalENBID,

) (PWSRestartIndicationIEField, error) {
	if b.inject == nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s21.BridgeGlobalENBIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSRestartIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSRestartIndicationGlobalENBIDIEBinding) Get(field *PWSRestartIndicationIEField) (*s21.GlobalENBID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSRestartIndicationTAIListForRestartIEBinding binds TAIListForRestart to the PWSRestartIndicationIEs object set of TS 36.413.
type PWSRestartIndicationTAIListForRestartIEBinding struct {
	info   s00.FieldInfo
	codec  s41.TAIListForRestartValueCodec
	inject func(s41.TAIListForRestart,

	) PWSRestartIndicationIEValue

	get func(*PWSRestartIndicationIEValue,

	) (*s41.TAIListForRestart,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSRestartIndicationTAIListForRestartIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSRestartIndicationTAIListForRestartIEBinding) Codec() s41.TAIListForRestartValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PWSRestartIndicationTAIListForRestartIEBinding) New(value s41.TAIListForRestart,

) (PWSRestartIndicationIEField, error) {
	if b.inject == nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s41.BridgeTAIListForRestartValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSRestartIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSRestartIndicationTAIListForRestartIEBinding) Get(field *PWSRestartIndicationIEField) (*s41.TAIListForRestart,

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

// ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding binds UEAssociatedLogicalS1ConnectionListResAck to the ResetAcknowledgeIEs object set of TS 36.413.
type ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding struct {
	info   s00.FieldInfo
	codec  s45.UEAssociatedLogicalS1ConnectionListResAckValueCodec
	inject func(s45.UEAssociatedLogicalS1ConnectionListResAck,

	) ResetAcknowledgeIEValue

	get func(*ResetAcknowledgeIEValue,

	) (*s45.UEAssociatedLogicalS1ConnectionListResAck,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) Codec() s45.UEAssociatedLogicalS1ConnectionListResAckValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) New(value s45.UEAssociatedLogicalS1ConnectionListResAck,

) (ResetAcknowledgeIEField, error) {
	if b.inject == nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s45.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return ResetAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) Get(field *ResetAcknowledgeIEField) (*s45.UEAssociatedLogicalS1ConnectionListResAck,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResetAcknowledgeCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the ResetAcknowledgeIEs object set of TS 36.413.
type ResetAcknowledgeCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s26.CriticalityDiagnosticsValueCodec
	inject func(s26.CriticalityDiagnostics,

	) ResetAcknowledgeIEValue

	get func(*ResetAcknowledgeIEValue,

	) (*s26.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ResetAcknowledgeCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetAcknowledgeCriticalityDiagnosticsIEBinding) Codec() s26.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ResetAcknowledgeCriticalityDiagnosticsIEBinding) New(value s26.CriticalityDiagnostics,

) (ResetAcknowledgeIEField, error) {
	if b.inject == nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return ResetAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ResetAcknowledgeCriticalityDiagnosticsIEBinding) Get(field *ResetAcknowledgeIEField) (*s26.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
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

// ResetAcknowledgeValueCodec is the concrete ValueCodec[ResetAcknowledge].
type ResetAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledge,

		error)
	encode func(ResetAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledge, aper.DecodeState,

	) (ResetAcknowledge, aper.Snapshot,

	)
	compare func(ResetAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeValueCodec) New(value ResetAcknowledge,

) (ResetAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeValueCodec) EncodeAPER(value ResetAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeValueCodec) encodeBudgetValue(value ResetAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeValueCodec) encodeChanged(value ResetAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNASTransportValueCodec is the concrete ValueCodec[UplinkNASTransport].
type UplinkNASTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNASTransport,

		error)
	encode func(UplinkNASTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNASTransport, aper.DecodeState,

	) (UplinkNASTransport, aper.Snapshot,

	)
	compare func(UplinkNASTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNASTransportValueCodec) New(value UplinkNASTransport,

) (UplinkNASTransportAPERValue, error) {
	if c.encode == nil {
		return UplinkNASTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNASTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNASTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNASTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNASTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNASTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNASTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNASTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNASTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNASTransportValueCodec) EncodeAPER(value UplinkNASTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UplinkNASTransportValueCodec) encodeBudgetValue(value UplinkNASTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNASTransportValueCodec) encodeChanged(value UplinkNASTransport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNonUEAssociatedLPPaTransportValueCodec is the concrete ValueCodec[UplinkNonUEAssociatedLPPaTransport].
type UplinkNonUEAssociatedLPPaTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNonUEAssociatedLPPaTransport,

		error)
	encode func(UplinkNonUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNonUEAssociatedLPPaTransport, aper.DecodeState,

	) (UplinkNonUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) New(value UplinkNonUEAssociatedLPPaTransport,

) (UplinkNonUEAssociatedLPPaTransportAPERValue, error) {
	if c.encode == nil {
		return UplinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNonUEAssociatedLPPaTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNonUEAssociatedLPPaTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNonUEAssociatedLPPaTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNonUEAssociatedLPPaTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNonUEAssociatedLPPaTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNonUEAssociatedLPPaTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) EncodeAPER(value UplinkNonUEAssociatedLPPaTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) encodeBudgetValue(value UplinkNonUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) encodeChanged(value UplinkNonUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingValueCodec is the concrete ValueCodec[UplinkS1cdma2000tunnelling].
type UplinkS1cdma2000tunnellingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnelling,

		error)
	encode func(UplinkS1cdma2000tunnelling,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnelling, aper.DecodeState,

	) (UplinkS1cdma2000tunnelling, aper.Snapshot,

	)
	compare func(UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingValueCodec) New(value UplinkS1cdma2000tunnelling,

) (UplinkS1cdma2000tunnellingAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UplinkS1cdma2000tunnellingValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnelling,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingValueCodec) encodeChanged(value UplinkS1cdma2000tunnelling,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkUEAssociatedLPPaTransportValueCodec is the concrete ValueCodec[UplinkUEAssociatedLPPaTransport].
type UplinkUEAssociatedLPPaTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkUEAssociatedLPPaTransport,

		error)
	encode func(UplinkUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkUEAssociatedLPPaTransport, aper.DecodeState,

	) (UplinkUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkUEAssociatedLPPaTransportValueCodec) New(value UplinkUEAssociatedLPPaTransport,

) (UplinkUEAssociatedLPPaTransportAPERValue, error) {
	if c.encode == nil {
		return UplinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkUEAssociatedLPPaTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkUEAssociatedLPPaTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkUEAssociatedLPPaTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkUEAssociatedLPPaTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkUEAssociatedLPPaTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkUEAssociatedLPPaTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkUEAssociatedLPPaTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkUEAssociatedLPPaTransportValueCodec) EncodeAPER(value UplinkUEAssociatedLPPaTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UplinkUEAssociatedLPPaTransportValueCodec) encodeBudgetValue(value UplinkUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkUEAssociatedLPPaTransportValueCodec) encodeChanged(value UplinkUEAssociatedLPPaTransport,

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
func BridgeUplinkNASTransportIEValueValidateS1APIEContainer(fields s41.UplinkNASTransportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s41.BridgeUplinkNASTransportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s41.BridgeUplinkNASTransportIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s41.BridgeUplinkNASTransportIEValueMethodRule(field.Value).Assignment
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
func BridgeResetAcknowledgeIEValueValidateS1APIEContainer(fields ResetAcknowledgeIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(fields s24.UplinkS1cdma2000tunnellingIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodRule(field.Value).Assignment
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
func BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields s14.UplinkUEAssociatedLPPaTransportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s14.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s14.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s14.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodRule(field.Value).Assignment
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
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields s14.UplinkNonUEAssociatedLPPaTransportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodRule(field.Value).Assignment
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
func BridgePWSRestartIndicationIEValueValidateS1APIEContainer(fields PWSRestartIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// PWSRestartIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PWSRestartIndicationIEs}} codec of TS 36.413.
func PWSRestartIndicationIEValueERABIEContainerListCodec(table s00.PWSRestartIndicationIEValueIETable) PWSRestartIndicationIEValueERABIEContainerListValueCodec {
	codec := PWSRestartIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PWSRestartIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return PWSRestartIndicationIEValueERABIEContainerListValueCodec{path: "PWSRestartIndicationIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PWSRestartIndicationIEValueERABIEContainerList
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
			return nil, runtime.WrapDecodePath(err, "PWSRestartIndicationIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PWSRestartIndicationIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PWSRestartIndicationIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value PWSRestartIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSRestartIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSRestartIndicationIEValueERABIEContainerList, options aper.DecodeState) (PWSRestartIndicationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v PWSRestartIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ResetAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ResetAcknowledgeIEs}} codec of TS 36.413.
func ResetAcknowledgeIEValueERABIEContainerListCodec(table s00.ResetAcknowledgeIEValueIETable) ResetAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := ResetAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ResetAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ResetAcknowledgeIEValueERABIEContainerListValueCodec{path: "ResetAcknowledgeIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetAcknowledgeIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetAcknowledgeIEField
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
			return nil, runtime.WrapDecodePath(err, "ResetAcknowledgeIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetAcknowledgeIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ResetAcknowledgeIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ResetAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v ResetAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ResetAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UplinkNASTransportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UplinkNASTransport-IEs}} codec of TS 36.413.
func UplinkNASTransportIEValueERABIEContainerListCodec(table s00.UplinkNASTransportIEValueIETable) s41.UplinkNASTransportIEValueERABIEContainerListValueCodec {
	codec := UplinkNASTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s41.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s41.UplinkNASTransportIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s41.UplinkNASTransportIEValueERABIEContainerListValueCodec {
		sealed := s41.UplinkNASTransportIEValueERABIEContainerListValueCodec{}
		*s41.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UplinkNASTransportIEValueERABIEContainerList"
		*s41.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.UplinkNASTransportIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s41.UplinkNASTransportIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s41.UplinkNASTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s41.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkNASTransportIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNASTransportIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkNASTransportIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s41.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s41.UplinkNASTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(&codec))(s41.UplinkNASTransportIEContainer(value), fresh, budget)
		}
		*s41.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s41.UplinkNASTransportIEValueERABIEContainerList, options aper.DecodeState) (s41.UplinkNASTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s41.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s41.UplinkNASTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UplinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable) s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
	codec := UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
		sealed := s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList"
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UplinkNonUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s14.UplinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UplinkS1cdma2000tunnellingIEs}} codec of TS 36.413.
func UplinkS1cdma2000tunnellingIEValueERABIEContainerListCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable) s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec {
	codec := UplinkS1cdma2000tunnellingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec {
		sealed := s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec{}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UplinkS1cdma2000tunnellingIEValueERABIEContainerList"
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UplinkS1cdma2000tunnellingIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkS1cdma2000tunnellingIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(&codec))(s24.UplinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UplinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable) s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
	codec := UplinkUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
		sealed := s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList"
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UplinkUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s14.UplinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UserLocationInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UserLocationInformation-ExtIEs}} codec of TS 36.413.
func UserLocationInformationExtIEsValueExtensionFieldTableCodec(table s00.UserLocationInformationExtIEsValueExtensionTable) s25.UserLocationInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeUserLocationInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s25.UserLocationInformationExtIEsExtFieldValueCodec{}
	}
	return func() s25.UserLocationInformationExtIEsExtFieldValueCodec {
		sealed := s25.UserLocationInformationExtIEsExtFieldValueCodec{}
		*s25.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "UserLocationInformationExtIEsExtField"
		*s25.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.UserLocationInformationExtIEsExtField, error) {
			var field s25.UserLocationInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s25.BridgeUserLocationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UserLocationInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UserLocationInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UserLocationInformationExtIEsExtField")
			}
			return field, nil
		}
		*s25.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s25.UserLocationInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s25.BridgeUserLocationInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s25.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s25.UserLocationInformationExtIEsExtField, options aper.DecodeState) (s25.UserLocationInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s25.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s25.UserLocationInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PWSRestartIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PWSRestartIndicationIEs}} codec of TS 36.413.
func PWSRestartIndicationIEValueIEFieldTableCodec(table s00.PWSRestartIndicationIEValueIETable) PWSRestartIndicationIEFieldValueCodec {
	if !*s00.BridgePWSRestartIndicationIEValueIETableFieldBound(&table) {
		return PWSRestartIndicationIEFieldValueCodec{}
	}
	return PWSRestartIndicationIEFieldValueCodec{path: "PWSRestartIndicationIEField", decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEField, error) {
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

// ResetAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ResetAcknowledgeIEs}} codec of TS 36.413.
func ResetAcknowledgeIEValueIEFieldTableCodec(table s00.ResetAcknowledgeIEValueIETable) ResetAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeResetAcknowledgeIEValueIETableFieldBound(&table) {
		return ResetAcknowledgeIEFieldValueCodec{}
	}
	return ResetAcknowledgeIEFieldValueCodec{path: "ResetAcknowledgeIEField", decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEField, error) {
		var field ResetAcknowledgeIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ResetAcknowledgeIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetAcknowledgeIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ResetAcknowledgeIEField")
		}
		return field, nil
	}, encode: func(field ResetAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ResetAcknowledgeIEField, options aper.DecodeState) (ResetAcknowledgeIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResetAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
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

// UplinkNASTransportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UplinkNASTransport-IEs}} codec of TS 36.413.
func UplinkNASTransportIEValueIEFieldTableCodec(table s00.UplinkNASTransportIEValueIETable) s41.UplinkNASTransportIEFieldValueCodec {
	if !*s00.BridgeUplinkNASTransportIEValueIETableFieldBound(&table) {
		return s41.UplinkNASTransportIEFieldValueCodec{}
	}
	return func() s41.UplinkNASTransportIEFieldValueCodec {
		sealed := s41.UplinkNASTransportIEFieldValueCodec{}
		*s41.BridgeUplinkNASTransportIEFieldValueCodecFieldPath(&sealed) = "UplinkNASTransportIEField"
		*s41.BridgeUplinkNASTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.UplinkNASTransportIEField, error) {
			var field s41.UplinkNASTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s41.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UplinkNASTransportIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNASTransportIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UplinkNASTransportIEField")
			}
			return field, nil
		}
		*s41.BridgeUplinkNASTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s41.UplinkNASTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s41.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s41.BridgeUplinkNASTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s41.UplinkNASTransportIEField, options aper.DecodeState) (s41.UplinkNASTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeUplinkNASTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s41.UplinkNASTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeUplinkNASTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UplinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable) s14.UplinkNonUEAssociatedLPPaTransportIEFieldValueCodec {
	if !*s00.BridgeUplinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s14.UplinkNonUEAssociatedLPPaTransportIEFieldValueCodec{}
	}
	return func() s14.UplinkNonUEAssociatedLPPaTransportIEFieldValueCodec {
		sealed := s14.UplinkNonUEAssociatedLPPaTransportIEFieldValueCodec{}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldPath(&sealed) = "UplinkNonUEAssociatedLPPaTransportIEField"
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEField, error) {
			var field s14.UplinkNonUEAssociatedLPPaTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNonUEAssociatedLPPaTransportIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEField")
			}
			return field, nil
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s14.UplinkNonUEAssociatedLPPaTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEField, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UplinkS1cdma2000tunnellingIEs}} codec of TS 36.413.
func UplinkS1cdma2000tunnellingIEValueIEFieldTableCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable) s24.UplinkS1cdma2000tunnellingIEFieldValueCodec {
	if !*s00.BridgeUplinkS1cdma2000tunnellingIEValueIETableFieldBound(&table) {
		return s24.UplinkS1cdma2000tunnellingIEFieldValueCodec{}
	}
	return func() s24.UplinkS1cdma2000tunnellingIEFieldValueCodec {
		sealed := s24.UplinkS1cdma2000tunnellingIEFieldValueCodec{}
		*s24.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldPath(&sealed) = "UplinkS1cdma2000tunnellingIEField"
		*s24.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEField, error) {
			var field s24.UplinkS1cdma2000tunnellingIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkS1cdma2000tunnellingIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEField")
			}
			return field, nil
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldEncode(&sealed) = func(field s24.UplinkS1cdma2000tunnellingIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldCapture(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEField, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldCompare(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UplinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable) s14.UplinkUEAssociatedLPPaTransportIEFieldValueCodec {
	if !*s00.BridgeUplinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s14.UplinkUEAssociatedLPPaTransportIEFieldValueCodec{}
	}
	return func() s14.UplinkUEAssociatedLPPaTransportIEFieldValueCodec {
		sealed := s14.UplinkUEAssociatedLPPaTransportIEFieldValueCodec{}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldPath(&sealed) = "UplinkUEAssociatedLPPaTransportIEField"
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEField, error) {
			var field s14.UplinkUEAssociatedLPPaTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkUEAssociatedLPPaTransportIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEField")
			}
			return field, nil
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s14.UplinkUEAssociatedLPPaTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEField, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
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
	return PWSRestartIndicationIEContainerValueCodec{path: "PWSRestartIndicationIEContainer", decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEContainer, error) {
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

// ResetAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{ResetAcknowledgeIEs}} codec of TS 36.413.
func ResetAcknowledgeIEValueIETableCodec(table s00.ResetAcknowledgeIEValueIETable, bounds aper.ListBounds) ResetAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeResetAcknowledgeIEValueIETableFieldBound(&table) {
		return ResetAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ResetAcknowledgeIEContainerValueCodec{path: "ResetAcknowledgeIEContainer", decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetAcknowledgeIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetAcknowledgeIEField
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
			return nil, runtime.WrapDecodePath(err, "ResetAcknowledgeIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetAcknowledgeIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ResetAcknowledgeIEContainer")
		}
		return fields, nil
	},
		encode: func(fields ResetAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ResetAcknowledgeIEContainer, options aper.DecodeState) (ResetAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ResetAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// UplinkNASTransportIEValueIETableCodec constructs the ProtocolIE-Container {{UplinkNASTransport-IEs}} codec of TS 36.413.
func UplinkNASTransportIEValueIETableCodec(table s00.UplinkNASTransportIEValueIETable, bounds aper.ListBounds) s41.UplinkNASTransportIEContainerValueCodec {
	if !*s00.BridgeUplinkNASTransportIEValueIETableFieldBound(&table) {
		return s41.UplinkNASTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s41.UplinkNASTransportIEContainerValueCodec {
		sealed := s41.UplinkNASTransportIEContainerValueCodec{}
		*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldPath(&sealed) = "UplinkNASTransportIEContainer"
		*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.UplinkNASTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s41.UplinkNASTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s41.UplinkNASTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s41.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkNASTransportIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNASTransportIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkNASTransportIEContainer")
			}
			return fields, nil
		}
		*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s41.UplinkNASTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s41.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s41.UplinkNASTransportIEContainer, options aper.DecodeState) (s41.UplinkNASTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s41.UplinkNASTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec constructs the ProtocolIE-Container {{UplinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s14.UplinkNonUEAssociatedLPPaTransportIEContainerValueCodec {
	if !*s00.BridgeUplinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s14.UplinkNonUEAssociatedLPPaTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.UplinkNonUEAssociatedLPPaTransportIEContainerValueCodec {
		sealed := s14.UplinkNonUEAssociatedLPPaTransportIEContainerValueCodec{}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldPath(&sealed) = "UplinkNonUEAssociatedLPPaTransportIEContainer"
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UplinkNonUEAssociatedLPPaTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UplinkNonUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNonUEAssociatedLPPaTransportIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEContainer")
			}
			return fields, nil
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s14.UplinkNonUEAssociatedLPPaTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEContainer, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueIETableCodec constructs the ProtocolIE-Container {{UplinkS1cdma2000tunnellingIEs}} codec of TS 36.413.
func UplinkS1cdma2000tunnellingIEValueIETableCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable, bounds aper.ListBounds) s24.UplinkS1cdma2000tunnellingIEContainerValueCodec {
	if !*s00.BridgeUplinkS1cdma2000tunnellingIEValueIETableFieldBound(&table) {
		return s24.UplinkS1cdma2000tunnellingIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s24.UplinkS1cdma2000tunnellingIEContainerValueCodec {
		sealed := s24.UplinkS1cdma2000tunnellingIEContainerValueCodec{}
		*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldPath(&sealed) = "UplinkS1cdma2000tunnellingIEContainer"
		*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UplinkS1cdma2000tunnellingIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UplinkS1cdma2000tunnellingIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkS1cdma2000tunnellingIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEContainer")
			}
			return fields, nil
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(&sealed) = func(fields s24.UplinkS1cdma2000tunnellingIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldCapture(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEContainer, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldCompare(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueIETableCodec constructs the ProtocolIE-Container {{UplinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkUEAssociatedLPPaTransportIEValueIETableCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s14.UplinkUEAssociatedLPPaTransportIEContainerValueCodec {
	if !*s00.BridgeUplinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s14.UplinkUEAssociatedLPPaTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.UplinkUEAssociatedLPPaTransportIEContainerValueCodec {
		sealed := s14.UplinkUEAssociatedLPPaTransportIEContainerValueCodec{}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldPath(&sealed) = "UplinkUEAssociatedLPPaTransportIEContainer"
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UplinkUEAssociatedLPPaTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UplinkUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkUEAssociatedLPPaTransportIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEContainer")
			}
			return fields, nil
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s14.UplinkUEAssociatedLPPaTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEContainer, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PWSRestartIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PWSRestartIndicationIEs}} codec of TS 36.413.
func PWSRestartIndicationIEValueProtocolErrorIEContainerListCodec(table s00.PWSRestartIndicationIEValueIETable) PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := PWSRestartIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec{path: "PWSRestartIndicationIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PWSRestartIndicationIEValueProtocolErrorIEContainerList
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
			return nil, runtime.WrapDecodePath(err, "PWSRestartIndicationIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PWSRestartIndicationIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PWSRestartIndicationIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value PWSRestartIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSRestartIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSRestartIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (PWSRestartIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v PWSRestartIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCompareS1APProtocolErrorIEContainerList(
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

// ResetAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ResetAcknowledgeIEs}} codec of TS 36.413.
func ResetAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.ResetAcknowledgeIEValueIETable) ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := ResetAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{path: "ResetAcknowledgeIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetAcknowledgeIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetAcknowledgeIEField
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
			return nil, runtime.WrapDecodePath(err, "ResetAcknowledgeIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetAcknowledgeIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ResetAcknowledgeIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value ResetAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v ResetAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResetAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(
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

// UplinkNASTransportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UplinkNASTransport-IEs}} codec of TS 36.413.
func UplinkNASTransportIEValueProtocolErrorIEContainerListCodec(table s00.UplinkNASTransportIEValueIETable) s41.UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := UplinkNASTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s41.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s41.UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s41.UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s41.UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s41.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UplinkNASTransportIEValueProtocolErrorIEContainerList"
		*s41.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.UplinkNASTransportIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s41.UplinkNASTransportIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s41.UplinkNASTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s41.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkNASTransportIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNASTransportIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkNASTransportIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s41.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s41.UplinkNASTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(&codec))(s41.UplinkNASTransportIEContainer(value), fresh, budget)
		}
		*s41.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s41.UplinkNASTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s41.UplinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s41.UplinkNASTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UplinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable) s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList"
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UplinkNonUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s14.UplinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UplinkS1cdma2000tunnellingIEs}} codec of TS 36.413.
func UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable) s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec {
	codec := UplinkS1cdma2000tunnellingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList"
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UplinkS1cdma2000tunnellingIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(&codec))(s24.UplinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UplinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable) s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := UplinkUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList"
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UplinkUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s14.UplinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PWSRestartIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PWSRestartIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PWSRestartIndicationIEValueProtocolIEContainerListCodec(table s00.PWSRestartIndicationIEValueIETable, bounds aper.ListBounds) PWSRestartIndicationIEValueProtocolIEContainerListValueCodec {
	codec := PWSRestartIndicationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return PWSRestartIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return PWSRestartIndicationIEValueProtocolIEContainerListValueCodec{path: "PWSRestartIndicationIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PWSRestartIndicationIEValueProtocolIEContainerList
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
			return nil, runtime.WrapDecodePath(err, "PWSRestartIndicationIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PWSRestartIndicationIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PWSRestartIndicationIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value PWSRestartIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSRestartIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSRestartIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (PWSRestartIndicationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v PWSRestartIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgePWSRestartIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// ResetAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ResetAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ResetAcknowledgeIEValueProtocolIEContainerListCodec(table s00.ResetAcknowledgeIEValueIETable, bounds aper.ListBounds) ResetAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := ResetAcknowledgeIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ResetAcknowledgeIEValueProtocolIEContainerListValueCodec{path: "ResetAcknowledgeIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetAcknowledgeIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetAcknowledgeIEField
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
			return nil, runtime.WrapDecodePath(err, "ResetAcknowledgeIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetAcknowledgeIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ResetAcknowledgeIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ResetAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v ResetAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ResetAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UplinkNASTransportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UplinkNASTransport-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UplinkNASTransportIEValueProtocolIEContainerListCodec(table s00.UplinkNASTransportIEValueIETable, bounds aper.ListBounds) s41.UplinkNASTransportIEValueProtocolIEContainerListValueCodec {
	codec := UplinkNASTransportIEValueIETableCodec(table, bounds)
	if *s41.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s41.UplinkNASTransportIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s41.UplinkNASTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s41.UplinkNASTransportIEValueProtocolIEContainerListValueCodec{}
		*s41.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UplinkNASTransportIEValueProtocolIEContainerList"
		*s41.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.UplinkNASTransportIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s41.UplinkNASTransportIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s41.UplinkNASTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s41.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkNASTransportIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNASTransportIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkNASTransportIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s41.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s41.UplinkNASTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s41.BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(&codec))(s41.UplinkNASTransportIEContainer(value), fresh, budget)
		}
		*s41.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s41.UplinkNASTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s41.UplinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s41.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s41.UplinkNASTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UplinkNonUEAssociatedLPPaTransport-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
	codec := UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, bounds)
	if *s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList"
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UplinkNonUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s14.UplinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UplinkS1cdma2000tunnellingIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable, bounds aper.ListBounds) s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec {
	codec := UplinkS1cdma2000tunnellingIEValueIETableCodec(table, bounds)
	if *s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec {
		sealed := s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList"
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UplinkS1cdma2000tunnellingIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(&codec))(s24.UplinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, options aper.DecodeState) (s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UplinkUEAssociatedLPPaTransport-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
	codec := UplinkUEAssociatedLPPaTransportIEValueIETableCodec(table, bounds)
	if *s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList"
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UplinkUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s14.UplinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// pWSRestartIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[PWSRestartIndicationIEValue].
type PWSRestartIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) PWSRestartIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (PWSRestartIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// resetAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[ResetAcknowledgeIEValue].
type ResetAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ResetAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ResetAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEField(v *ResetAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolIEField(v *ResetAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uplinkNASTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[UplinkNASTransportIEValue].
type UplinkNASTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s41.UplinkNASTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s41.UplinkNASTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEField(v *s41.UplinkNASTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s41.BridgeUplinkNASTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s41.BridgeUplinkNASTransportIEFieldFieldReplay(v), *s41.BridgeUplinkNASTransportIEFieldFieldWithoutReplay(v))
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolIEField(v *s41.UplinkNASTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s41.BridgeUplinkNASTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s41.BridgeUplinkNASTransportIEFieldFieldReplay(v), *s41.BridgeUplinkNASTransportIEFieldFieldWithoutReplay(v))
}

// uplinkNonUEAssociatedLPPaTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[UplinkNonUEAssociatedLPPaTransportIEValue].
type UplinkNonUEAssociatedLPPaTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s14.UplinkNonUEAssociatedLPPaTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s14.UplinkNonUEAssociatedLPPaTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v *s14.UplinkNonUEAssociatedLPPaTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v *s14.UplinkNonUEAssociatedLPPaTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}

// uplinkS1cdma2000tunnellingIEValueProtocolOpenValue is the concrete protocolOpenValue[UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s24.UplinkS1cdma2000tunnellingIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s24.UplinkS1cdma2000tunnellingIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(v *s24.UplinkS1cdma2000tunnellingIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s24.BridgeUplinkS1cdma2000tunnellingIEFieldFieldReplay(v), *s24.BridgeUplinkS1cdma2000tunnellingIEFieldFieldWithoutReplay(v))
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(v *s24.UplinkS1cdma2000tunnellingIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s24.BridgeUplinkS1cdma2000tunnellingIEFieldFieldReplay(v), *s24.BridgeUplinkS1cdma2000tunnellingIEFieldFieldWithoutReplay(v))
}

// uplinkUEAssociatedLPPaTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[UplinkUEAssociatedLPPaTransportIEValue].
type UplinkUEAssociatedLPPaTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s14.UplinkUEAssociatedLPPaTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s14.UplinkUEAssociatedLPPaTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v *s14.UplinkUEAssociatedLPPaTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s14.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v *s14.UplinkUEAssociatedLPPaTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s14.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s25.UserLocationInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s25.BridgeUserLocationInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s25.BridgeUserLocationInformationExtIEsExtFieldFieldReplay(v), *s25.BridgeUserLocationInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionField(v *s25.UserLocationInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s25.BridgeUserLocationInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s25.BridgeUserLocationInformationExtIEsExtFieldFieldReplay(v), *s25.BridgeUserLocationInformationExtIEsExtFieldFieldWithoutReplay(v))
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

// ResetAcknowledgeAPERValue is the concrete APERValue[ResetAcknowledge].
type ResetAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResetAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeAPERValue) WithoutReplay() ResetAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNASTransportAPERValue is the concrete APERValue[UplinkNASTransport].
type UplinkNASTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   UplinkNASTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNASTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNASTransportAPERValue) WithoutReplay() UplinkNASTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNonUEAssociatedLPPaTransportAPERValue is the concrete APERValue[UplinkNonUEAssociatedLPPaTransport].
type UplinkNonUEAssociatedLPPaTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   UplinkNonUEAssociatedLPPaTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNonUEAssociatedLPPaTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNonUEAssociatedLPPaTransportAPERValue) WithoutReplay() UplinkNonUEAssociatedLPPaTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingAPERValue is the concrete APERValue[UplinkS1cdma2000tunnelling].
type UplinkS1cdma2000tunnellingAPERValue struct {
	context s00.BridgeCodecContext
	Value   UplinkS1cdma2000tunnelling

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkUEAssociatedLPPaTransportAPERValue is the concrete APERValue[UplinkUEAssociatedLPPaTransport].
type UplinkUEAssociatedLPPaTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   UplinkUEAssociatedLPPaTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkUEAssociatedLPPaTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkUEAssociatedLPPaTransportAPERValue) WithoutReplay() UplinkUEAssociatedLPPaTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
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

// ResetAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ResetAcknowledgeIEValueERABIEContainerList].
type ResetAcknowledgeIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, error)
	encode  func(ResetAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, aper.Snapshot)
	compare func(ResetAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) New(value ResetAcknowledgeIEValueERABIEContainerList) (ResetAcknowledgeIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) EncodeAPER(value ResetAcknowledgeIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ResetAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) encodeChanged(value ResetAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ResetAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type ResetAcknowledgeIEValueERABIEContainerList []ResetAcknowledgeIEValueProtocolIESingleContainer

func BridgeResetAcknowledgeIEValueCaptureS1APERABIEContainerList(v *ResetAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APERABIEContainerList(v *ResetAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APERABIEContainerList(v *s41.UplinkNASTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APERABIEContainerList(v *s41.UplinkNASTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(v *s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(v *s14.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APERABIEContainerList(v *s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APERABIEContainerList(v *s24.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(v *s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(v *s14.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
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

// ResetAcknowledgeIEFieldValueCodec is the concrete ValueCodec[ResetAcknowledgeIEField].
type ResetAcknowledgeIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEField, error)
	encode  func(ResetAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEField, aper.DecodeState) (ResetAcknowledgeIEField, aper.Snapshot)
	compare func(ResetAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEFieldValueCodec) New(value ResetAcknowledgeIEField) (ResetAcknowledgeIEFieldAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEFieldValueCodec) EncodeAPER(value ResetAcknowledgeIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEFieldValueCodec) encodeBudgetValue(value ResetAcknowledgeIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEFieldValueCodec) encodeChanged(value ResetAcknowledgeIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// ResetAcknowledgeIEContainerValueCodec is the concrete ValueCodec[ResetAcknowledgeIEContainer].
type ResetAcknowledgeIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEContainer, error)
	encode  func(ResetAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEContainer, aper.DecodeState) (ResetAcknowledgeIEContainer, aper.Snapshot)
	compare func(ResetAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEContainerValueCodec) New(value ResetAcknowledgeIEContainer) (ResetAcknowledgeIEContainerAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEContainerValueCodec) EncodeAPER(value ResetAcknowledgeIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEContainerValueCodec) encodeBudgetValue(value ResetAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEContainerValueCodec) encodeChanged(value ResetAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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
func BridgePWSRestartIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *PWSRestartIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ResetAcknowledgeIEValueProtocolErrorIEContainerList].
type ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, error)
	encode  func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) New(value ResetAcknowledgeIEValueProtocolErrorIEContainerList) (ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ResetAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ResetAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ResetAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type ResetAcknowledgeIEValueProtocolErrorIEContainerList []ResetAcknowledgeIEValueProtocolIESingleContainer

func BridgeResetAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *ResetAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *ResetAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s41.UplinkNASTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s41.UplinkNASTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolErrorIEContainerList(v *s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolErrorIEContainerList(v *s24.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s14.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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
func BridgePWSRestartIndicationIEValueCompareS1APProtocolIEContainerList(v *PWSRestartIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// ResetAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ResetAcknowledgeIEValueProtocolIEContainerList].
type ResetAcknowledgeIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, error)
	encode  func(ResetAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ResetAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) New(value ResetAcknowledgeIEValueProtocolIEContainerList) (ResetAcknowledgeIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ResetAcknowledgeIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ResetAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeChanged(value ResetAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ResetAcknowledgeIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ResetAcknowledgeIEValueProtocolIEContainerList []ResetAcknowledgeIEValueProtocolIESingleContainer

func BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *ResetAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *ResetAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainerList(v *s41.UplinkNASTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainerList(v *s41.UplinkNASTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(v *s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(v *s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainerList(v *s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainerList(v *s24.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(v *s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(v *s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
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

// ResetAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[ResetAcknowledgeIEValueERABIEContainerList].
type ResetAcknowledgeIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEValueERABIEContainerListAPERValue) WithoutReplay() ResetAcknowledgeIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAcknowledgeIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ResetAcknowledgeIEs}} of TS 36.413: a single information element field.
type ResetAcknowledgeIEValueProtocolIESingleContainer = ResetAcknowledgeIEField

func BridgeResetAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *ResetAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *ResetAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(v *s41.UplinkNASTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolIESingleContainer(v *s41.UplinkNASTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNASTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(v *s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(v *s14.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(v *s24.UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(v *s24.UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(v *s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(v *s14.UplinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
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

// ResetAcknowledgeIEFieldAPERValue is the concrete APERValue[ResetAcknowledgeIEField].
type ResetAcknowledgeIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEFieldAPERValue) WithoutReplay() ResetAcknowledgeIEFieldAPERValue {
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

// ResetAcknowledgeIEContainerAPERValue is the concrete APERValue[ResetAcknowledgeIEContainer].
type ResetAcknowledgeIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEContainerAPERValue) WithoutReplay() ResetAcknowledgeIEContainerAPERValue {
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

// ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ResetAcknowledgeIEValueProtocolErrorIEContainerList].
type ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue {
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

// ResetAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ResetAcknowledgeIEValueProtocolIEContainerList].
type ResetAcknowledgeIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEValueProtocolIEContainerListAPERValue) WithoutReplay() ResetAcknowledgeIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
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
					s25.BridgeCaptureS1APECGIListForRestart(v.rowECGIListForRestart, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s21.BridgeCaptureS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(188):
			{
				f := s.Begin()
				s.Bool(v.rowTAIListForRestart == nil)
				if v.rowTAIListForRestart != nil {
					s41.BridgeCaptureS1APTAIListForRestart(v.rowTAIListForRestart, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s28.BridgeCompareS1APECGIListForRestart(v.rowECGIListForRestart, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s21.BridgeCompareS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(188):
			{
				f := s.Begin()
				s.Bool(v.rowTAIListForRestart == nil)
				if v.rowTAIListForRestart != nil {
					s41.BridgeCompareS1APTAIListForRestart(v.rowTAIListForRestart, s)
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
func BridgeCaptureS1APResetAcknowledge(v *ResetAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APResetAcknowledge(v *ResetAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APResetAcknowledgeIEValue(v *ResetAcknowledgeIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(93):
			{
				f := s.Begin()
				s.Bool(v.rowUEAssociatedLogicalS1ConnectionListResAck == nil)
				if v.rowUEAssociatedLogicalS1ConnectionListResAck != nil {
					s45.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAck(v.rowUEAssociatedLogicalS1ConnectionListResAck, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ResetAcknowledgeIEValue) captureSemantics(s aper.SemanticCapture) ResetAcknowledgeIEValue {
	BridgeCaptureS1APResetAcknowledgeIEValue(&v, &s)
	return v
}
func BridgeCompareS1APResetAcknowledgeIEValue(v *ResetAcknowledgeIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(93):
			{
				f := s.Begin()
				s.Bool(v.rowUEAssociatedLogicalS1ConnectionListResAck == nil)
				if v.rowUEAssociatedLogicalS1ConnectionListResAck != nil {
					s45.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAck(v.rowUEAssociatedLogicalS1ConnectionListResAck, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ResetAcknowledgeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APResetAcknowledgeIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APTAIBroadcastComplete(v *TAIBroadcastComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCaptureS1APTAIBroadcast(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIBroadcastComplete(v *TAIBroadcastComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCompareS1APTAIBroadcast(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAICancelledComplete(v *TAICancelledComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCaptureS1APTAICancelled(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAICancelledComplete(v *TAICancelledComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCompareS1APTAICancelled(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListComplete(v *TAIListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s42.BridgeCaptureS1APTAIList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListComplete(v *TAIListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s42.BridgeCompareS1APTAIList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListForRestartComplete(v *TAIListForRestartComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCaptureS1APTAIListForRestart(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListForRestartComplete(v *TAIListForRestartComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCompareS1APTAIListForRestart(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListforMDTComplete(v *TAIListforMDTComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCaptureS1APTAIListforMDT(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListforMDTComplete(v *TAIListforMDTComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCompareS1APTAIListforMDT(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListforQMCComplete(v *TAIListforQMCComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCaptureS1APTAIListforQMC(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListforQMCComplete(v *TAIListforQMCComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCompareS1APTAIListforQMC(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListforWarningComplete(v *TAIListforWarningComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCaptureS1APTAIListforWarning(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListforWarningComplete(v *TAIListforWarningComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCompareS1APTAIListforWarning(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAListforMDTComplete(v *TAListforMDTComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTAListforMDT(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAListforMDTComplete(v *TAListforMDTComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APTAListforMDT(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAListforQMCComplete(v *TAListforQMCComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTAListforQMC(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAListforQMCComplete(v *TAListforQMCComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APTAListforQMC(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAckComplete(v *UEAssociatedLogicalS1ConnectionListResAckComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s45.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAck(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAckComplete(v *UEAssociatedLogicalS1ConnectionListResAckComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s45.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAck(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResComplete(v *UEAssociatedLogicalS1ConnectionListResComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s45.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListRes(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResComplete(v *UEAssociatedLogicalS1ConnectionListResComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s45.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListRes(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEHistoryInformationComplete(v *UEHistoryInformationComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s52.BridgeCaptureS1APUEHistoryInformation(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEHistoryInformationComplete(v *UEHistoryInformationComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s52.BridgeCompareS1APUEHistoryInformation(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUplinkNASTransport(v *UplinkNASTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUplinkNASTransport(v *UplinkNASTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUplinkNonUEAssociatedLPPaTransport(v *UplinkNonUEAssociatedLPPaTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(v *UplinkNonUEAssociatedLPPaTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUplinkS1cdma2000tunnelling(v *UplinkS1cdma2000tunnelling, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUplinkS1cdma2000tunnelling(v *UplinkS1cdma2000tunnelling, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUplinkUEAssociatedLPPaTransport(v *UplinkUEAssociatedLPPaTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUplinkUEAssociatedLPPaTransport(v *UplinkUEAssociatedLPPaTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUserLocationInformation(v *UserLocationInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s20.BridgeCaptureS1APEUTRANCGI(&v.EutranCgi, s)
	s40.BridgeCaptureS1APTAI(&v.Tai, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUserLocationInformation(v *UserLocationInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s20.BridgeCompareS1APEUTRANCGI(&v.EutranCgi, s)
	s40.BridgeCompareS1APTAI(&v.Tai, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APWLANMeasConfigNameListComplete(v *WLANMeasConfigNameListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APWLANMeasConfigNameList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWLANMeasConfigNameListComplete(v *WLANMeasConfigNameListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APWLANMeasConfigNameList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

// UserLocationInformation represents the ASN.1 type UserLocationInformation (SEQUENCE).
type UserLocationInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	EutranCgi         s20.EUTRANCGI                                 `asn1:"tag:0,context,implicit"`
	Tai               s40.TAI                                       `asn1:"tag:1,context,implicit"`
	IEExtensions      s25.UserLocationInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// TAIListforMDTComplete carries a complete TAIListforMDT encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListforMDTComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s41.TAIListforMDT
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListforMDTComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s42.BridgeMarshalAPERTAIListforMDTTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIListforMDT from APER format.
func (v *TAIListforMDTComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAIListforMDTComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIListforMDT")
	}
	bb.EnterComponent("TAIListforMDT")
	value, err := BridgeUnmarshalAPERTAIListforMDTFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIListforMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforMDT")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIListforMDT encodes a TAIListforMDT list to APER.
func BridgeMarshalAPERTAIListforMDT(list TAIListforMDTComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAIListforMDT decodes a TAIListforMDT list from APER.
func BridgeUnmarshalAPERTAIListforMDT(data []byte) (TAIListforMDTComplete, error) {
	var value TAIListforMDTComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListforMDTFrom decodes a TAIListforMDT list from bb.
func BridgeUnmarshalAPERTAIListforMDTFrom(bb *aper.BitBuffer) (s41.TAIListforMDT, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s41.BridgeAsn1cAPERTAIListforMDTListValue
	if err := BridgeUnmarshalAPERTAIListforMDTInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListforMDTInto(v *s41.BridgeAsn1cAPERTAIListforMDTListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s41.TAIListforMDT, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s40.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// TAIListforWarningComplete carries a complete TAIListforWarning encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListforWarningComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s41.TAIListforWarning
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListforWarningComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s42.BridgeMarshalAPERTAIListforWarningTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIListforWarning from APER format.
func (v *TAIListforWarningComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAIListforWarningComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIListforWarning")
	}
	bb.EnterComponent("TAIListforWarning")
	value, err := BridgeUnmarshalAPERTAIListforWarningFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforWarning")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIListforWarning")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforWarning")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIListforWarning encodes a TAIListforWarning list to APER.
func BridgeMarshalAPERTAIListforWarning(list TAIListforWarningComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAIListforWarning decodes a TAIListforWarning list from APER.
func BridgeUnmarshalAPERTAIListforWarning(data []byte) (TAIListforWarningComplete, error) {
	var value TAIListforWarningComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListforWarningFrom decodes a TAIListforWarning list from bb.
func BridgeUnmarshalAPERTAIListforWarningFrom(bb *aper.BitBuffer) (s41.TAIListforWarning, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s41.BridgeAsn1cAPERTAIListforWarningListValue
	if err := BridgeUnmarshalAPERTAIListforWarningInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListforWarningInto(v *s41.BridgeAsn1cAPERTAIListforWarningListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s41.TAIListforWarning, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s40.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	Value            s41.TAIBroadcast
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIBroadcastComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s42.BridgeMarshalAPERTAIBroadcastTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIBroadcast from APER format.
func (v *TAIBroadcastComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAIBroadcastComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIBroadcast")
	}
	bb.EnterComponent("TAIBroadcast")
	value, err := s54.BridgeUnmarshalAPERTAIBroadcastFrom(bb)
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
	Value            s41.TAICancelled
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAICancelledComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s42.BridgeMarshalAPERTAICancelledTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAICancelled from APER format.
func (v *TAICancelledComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
func BridgeUnmarshalAPERTAICancelledFrom(bb *aper.BitBuffer) (s41.TAICancelled, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s41.BridgeAsn1cAPERTAICancelledListValue
	if err := BridgeUnmarshalAPERTAICancelledInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAICancelledInto(v *s41.BridgeAsn1cAPERTAICancelledListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s41.TAICancelled, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s41.TAICancelledItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s41.BridgeTAICancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// TAListforMDTComplete carries a complete TAListforMDT encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAListforMDTComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.TAListforMDT
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAListforMDTComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERTAListforMDTTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAListforMDT from APER format.
func (v *TAListforMDTComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAListforMDTComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAListforMDT")
	}
	bb.EnterComponent("TAListforMDT")
	value, err := BridgeUnmarshalAPERTAListforMDTFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAListforMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAListforMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAListforMDT")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAListforMDT encodes a TAListforMDT list to APER.
func BridgeMarshalAPERTAListforMDT(list TAListforMDTComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAListforMDT decodes a TAListforMDT list from APER.
func BridgeUnmarshalAPERTAListforMDT(data []byte) (TAListforMDTComplete, error) {
	var value TAListforMDTComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAListforMDTFrom decodes a TAListforMDT list from bb.
func BridgeUnmarshalAPERTAListforMDTFrom(bb *aper.BitBuffer) (s00.TAListforMDT, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERTAListforMDTListValue
	if err := BridgeUnmarshalAPERTAListforMDTInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAListforMDTInto(v *s00.BridgeAsn1cAPERTAListforMDTListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.TAListforMDT, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// TAListforQMCComplete carries a complete TAListforQMC encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAListforQMCComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.TAListforQMC
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAListforQMCComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERTAListforQMCTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAListforQMC from APER format.
func (v *TAListforQMCComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAListforQMCComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAListforQMC")
	}
	bb.EnterComponent("TAListforQMC")
	value, err := BridgeUnmarshalAPERTAListforQMCFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAListforQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAListforQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAListforQMC")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAListforQMC encodes a TAListforQMC list to APER.
func BridgeMarshalAPERTAListforQMC(list TAListforQMCComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAListforQMC decodes a TAListforQMC list from APER.
func BridgeUnmarshalAPERTAListforQMC(data []byte) (TAListforQMCComplete, error) {
	var value TAListforQMCComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAListforQMCFrom decodes a TAListforQMC list from bb.
func BridgeUnmarshalAPERTAListforQMCFrom(bb *aper.BitBuffer) (s00.TAListforQMC, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERTAListforQMCListValue
	if err := BridgeUnmarshalAPERTAListforQMCInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAListforQMCInto(v *s00.BridgeAsn1cAPERTAListforQMCListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.TAListforQMC, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// TAIListforQMCComplete carries a complete TAIListforQMC encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListforQMCComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s41.TAIListforQMC
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListforQMCComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s42.BridgeMarshalAPERTAIListforQMCTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIListforQMC from APER format.
func (v *TAIListforQMCComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAIListforQMCComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIListforQMC")
	}
	bb.EnterComponent("TAIListforQMC")
	value, err := BridgeUnmarshalAPERTAIListforQMCFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIListforQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforQMC")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIListforQMC encodes a TAIListforQMC list to APER.
func BridgeMarshalAPERTAIListforQMC(list TAIListforQMCComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAIListforQMC decodes a TAIListforQMC list from APER.
func BridgeUnmarshalAPERTAIListforQMC(data []byte) (TAIListforQMCComplete, error) {
	var value TAIListforQMCComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListforQMCFrom decodes a TAIListforQMC list from bb.
func BridgeUnmarshalAPERTAIListforQMCFrom(bb *aper.BitBuffer) (s41.TAIListforQMC, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s41.BridgeAsn1cAPERTAIListforQMCListValue
	if err := BridgeUnmarshalAPERTAIListforQMCInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListforQMCInto(v *s41.BridgeAsn1cAPERTAIListforQMCListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s41.TAIListforQMC, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s40.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	Value            s41.TAIListForRestart
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListForRestartComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s42.BridgeMarshalAPERTAIListForRestartTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIListForRestart from APER format.
func (v *TAIListForRestartComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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

// UnmarshalAPERTAIListForRestart decodes a TAIListForRestart list from APER.
func BridgeUnmarshalAPERTAIListForRestart(data []byte) (TAIListForRestartComplete, error) {
	var value TAIListForRestartComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListForRestartFrom decodes a TAIListForRestart list from bb.
func BridgeUnmarshalAPERTAIListForRestartFrom(bb *aper.BitBuffer) (s41.TAIListForRestart, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s41.BridgeAsn1cAPERTAIListForRestartListValue
	if err := BridgeUnmarshalAPERTAIListForRestartInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListForRestartInto(v *s41.BridgeAsn1cAPERTAIListForRestartListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s41.TAIListForRestart, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s40.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// UEHistoryInformationComplete carries a complete UEHistoryInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type UEHistoryInformationComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s52.UEHistoryInformation
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *UEHistoryInformationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s52.BridgeMarshalAPERUEHistoryInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes UEHistoryInformation from APER format.
func (v *UEHistoryInformationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UEHistoryInformationComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEHistoryInformation")
	}
	bb.EnterComponent("UEHistoryInformation")
	value, err := BridgeUnmarshalAPERUEHistoryInformationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEHistoryInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEHistoryInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEHistoryInformation")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERUEHistoryInformation encodes a UEHistoryInformation list to APER.
func BridgeMarshalAPERUEHistoryInformation(list UEHistoryInformationComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERUEHistoryInformation decodes a UEHistoryInformation list from APER.
func BridgeUnmarshalAPERUEHistoryInformation(data []byte) (UEHistoryInformationComplete, error) {
	var value UEHistoryInformationComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERUEHistoryInformationFrom decodes a UEHistoryInformation list from bb.
func BridgeUnmarshalAPERUEHistoryInformationFrom(bb *aper.BitBuffer) (s52.UEHistoryInformation, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s52.BridgeAsn1cAPERUEHistoryInformationListValue
	if err := BridgeUnmarshalAPERUEHistoryInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERUEHistoryInformationInto(v *s52.BridgeAsn1cAPERUEHistoryInformationListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s52.UEHistoryInformation, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s52.LastVisitedCellItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s52.BridgeLastVisitedCellItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UserLocationInformation to APER format.
func (v *UserLocationInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UserLocationInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&v.EutranCgi, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eutran-cgi: %w", err)
	}
	if err := s40.BridgeTAIMethodMarshalAPERTo(&v.Tai, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding tai: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s25.BridgeUserLocationInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UserLocationInformation from APER format.
func (v *UserLocationInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UserLocationInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UserLocationInformation")
	}
	bb.EnterComponent("UserLocationInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UserLocationInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "UserLocationInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "UserLocationInformation")
	}
	v.perPadding = padding
	return nil
}
func (v *UserLocationInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UserLocationInformation{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_eutrancgi := bb.EnterComponent("EutranCgi")
	if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&v.EutranCgi, bb); err != nil {
		return runtime.WrapDecodePath(err, "EutranCgi")
	}
	bb.LeaveComponent(toleranceMark_eutrancgi)
	toleranceMark_tai := bb.EnterComponent("Tai")
	if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&v.Tai, bb); err != nil {
		return runtime.WrapDecodePath(err, "Tai")
	}
	bb.LeaveComponent(toleranceMark_tai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s25.UserLocationInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s25.UserLocationInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s25.BridgeUserLocationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// WLANMeasConfigNameListComplete carries a complete WLANMeasConfigNameList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasConfigNameListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.WLANMeasConfigNameList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *WLANMeasConfigNameListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERWLANMeasConfigNameListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANMeasConfigNameList from APER format.
func (v *WLANMeasConfigNameListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *WLANMeasConfigNameListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	bb.EnterComponent("WLANMeasConfigNameList")
	value, err := BridgeUnmarshalAPERWLANMeasConfigNameListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANMeasConfigNameList")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANMeasConfigNameList encodes a WLANMeasConfigNameList list to APER.
func BridgeMarshalAPERWLANMeasConfigNameList(list WLANMeasConfigNameListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERWLANMeasConfigNameList decodes a WLANMeasConfigNameList list from APER.
func BridgeUnmarshalAPERWLANMeasConfigNameList(data []byte) (WLANMeasConfigNameListComplete, error) {
	var value WLANMeasConfigNameListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERWLANMeasConfigNameListFrom decodes a WLANMeasConfigNameList list from bb.
func BridgeUnmarshalAPERWLANMeasConfigNameListFrom(bb *aper.BitBuffer) (s00.WLANMeasConfigNameList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERWLANMeasConfigNameListListValue
	if err := BridgeUnmarshalAPERWLANMeasConfigNameListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERWLANMeasConfigNameListInto(v *s00.BridgeAsn1cAPERWLANMeasConfigNameListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.WLANMeasConfigNameList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 1, 32, true)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIBroadcastComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIBroadcastComplete", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAICancelledComplete", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListForRestartComplete", v.receivedLocation, v.perPadding)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListforMDTComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListforMDTComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListforMDTComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListforMDTComplete) WithoutReplay() TAIListforMDTComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListforMDTComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListforQMCComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListforQMCComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListforQMCComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListforQMCComplete) WithoutReplay() TAIListforQMCComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListforQMCComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListforWarningComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListforWarningComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListforWarningComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListforWarningComplete) WithoutReplay() TAIListforWarningComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListforWarningComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAListforMDTComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAListforMDTComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAListforMDTComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAListforMDTComplete) WithoutReplay() TAListforMDTComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAListforMDTComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAListforQMCComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAListforQMCComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAListforQMCComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAListforQMCComplete) WithoutReplay() TAListforQMCComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAListforQMCComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEHistoryInformationComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEHistoryInformationComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEHistoryInformationComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEHistoryInformationComplete) WithoutReplay() UEHistoryInformationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEHistoryInformationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UserLocationInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UserLocationInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UserLocationInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UserLocationInformation) WithoutReplay() UserLocationInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UserLocationInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasConfigNameListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasConfigNameListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WLANMeasConfigNameListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasConfigNameListComplete) WithoutReplay() WLANMeasConfigNameListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WLANMeasConfigNameListComplete
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *UserLocationInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UserLocationInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UserLocationInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UserLocationInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UserLocationInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UserLocationInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UserLocationInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
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
	if err := s42.BridgeMarshalAPERTAIBroadcastTo(v.Value, bb, fresh); err != nil {
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
	if err := s42.BridgeMarshalAPERTAICancelledTo(v.Value, bb, fresh); err != nil {
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
	if err := s42.BridgeMarshalAPERTAIListForRestartTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAIListforMDTComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListforMDTComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListforMDTComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListforMDTComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListforMDTComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListforMDTComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListforMDTComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListforMDTComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListforMDTComplete")
}
func (v *TAIListforMDTComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListforMDTComplete")
}
func (v *TAIListforMDTComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListforMDTComplete(v, &s)
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
func (v *TAIListforMDTComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListforMDTComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s42.BridgeMarshalAPERTAIListforMDTTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAIListforQMCComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListforQMCComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListforQMCComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListforQMCComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListforQMCComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListforQMCComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListforQMCComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListforQMCComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListforQMCComplete")
}
func (v *TAIListforQMCComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListforQMCComplete")
}
func (v *TAIListforQMCComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListforQMCComplete(v, &s)
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
func (v *TAIListforQMCComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListforQMCComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s42.BridgeMarshalAPERTAIListforQMCTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAIListforWarningComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListforWarningComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListforWarningComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListforWarningComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListforWarningComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListforWarningComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListforWarningComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListforWarningComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListforWarningComplete")
}
func (v *TAIListforWarningComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListforWarningComplete")
}
func (v *TAIListforWarningComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListforWarningComplete(v, &s)
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
func (v *TAIListforWarningComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListforWarningComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s42.BridgeMarshalAPERTAIListforWarningTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAListforMDTComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAListforMDTComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAListforMDTComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAListforMDTComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAListforMDTComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAListforMDTComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAListforMDTComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAListforMDTComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAListforMDTComplete")
}
func (v *TAListforMDTComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAListforMDTComplete")
}
func (v *TAListforMDTComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAListforMDTComplete(v, &s)
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
func (v *TAListforMDTComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAListforMDTComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s16.BridgeMarshalAPERTAListforMDTTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAListforQMCComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAListforQMCComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAListforQMCComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAListforQMCComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAListforQMCComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAListforQMCComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAListforQMCComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAListforQMCComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAListforQMCComplete")
}
func (v *TAListforQMCComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAListforQMCComplete")
}
func (v *TAListforQMCComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAListforQMCComplete(v, &s)
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
func (v *TAListforQMCComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAListforQMCComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s16.BridgeMarshalAPERTAListforQMCTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEHistoryInformationComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEHistoryInformationComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEHistoryInformationComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEHistoryInformationComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEHistoryInformationComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEHistoryInformationComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEHistoryInformationComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEHistoryInformationComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEHistoryInformationComplete")
}
func (v *UEHistoryInformationComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEHistoryInformationComplete")
}
func (v *UEHistoryInformationComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEHistoryInformationComplete(v, &s)
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
func (v *UEHistoryInformationComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEHistoryInformationComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s52.BridgeMarshalAPERUEHistoryInformationTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UserLocationInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UserLocationInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UserLocationInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UserLocationInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUserLocationInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UserLocationInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UserLocationInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UserLocationInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UserLocationInformation")
}
func (v *UserLocationInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UserLocationInformation")
}
func (v *UserLocationInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUserLocationInformation(v, &s)
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
func (v *UserLocationInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UserLocationInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *WLANMeasConfigNameListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WLANMeasConfigNameListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WLANMeasConfigNameListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANMeasConfigNameListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWLANMeasConfigNameListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WLANMeasConfigNameListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WLANMeasConfigNameListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
}
func (v *WLANMeasConfigNameListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
}
func (v *WLANMeasConfigNameListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWLANMeasConfigNameListComplete(v, &s)
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
func (v *WLANMeasConfigNameListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WLANMeasConfigNameListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s16.BridgeMarshalAPERWLANMeasConfigNameListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListforMDTComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListforMDTComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListforMDTComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListforMDTComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListforMDTComplete{}
		return report, aper.OperationError(err, "TAIListforMDTComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListforMDTComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListforQMCComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListforQMCComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListforQMCComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListforQMCComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListforQMCComplete{}
		return report, aper.OperationError(err, "TAIListforQMCComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListforQMCComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListforWarningComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListforWarningComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListforWarningComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListforWarningComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListforWarningComplete{}
		return report, aper.OperationError(err, "TAIListforWarningComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListforWarningComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAListforMDTComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAListforMDTComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAListforMDTComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAListforMDTComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAListforMDTComplete{}
		return report, aper.OperationError(err, "TAListforMDTComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAListforMDTComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAListforQMCComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAListforQMCComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAListforQMCComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAListforQMCComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAListforQMCComplete{}
		return report, aper.OperationError(err, "TAListforQMCComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAListforQMCComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEHistoryInformationComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEHistoryInformationComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEHistoryInformationComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEHistoryInformationComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEHistoryInformationComplete{}
		return report, aper.OperationError(err, "UEHistoryInformationComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEHistoryInformationComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UserLocationInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UserLocationInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UserLocationInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUserLocationInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UserLocationInformation{}
		return report, aper.OperationError(err, "UserLocationInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UserLocationInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *WLANMeasConfigNameListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANMeasConfigNameListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WLANMeasConfigNameListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWLANMeasConfigNameListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WLANMeasConfigNameListComplete{}
		return report, aper.OperationError(err, "WLANMeasConfigNameListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANMeasConfigNameListComplete")
}

// MarshalAPERTAIListforMDT encodes a complete named list.
func MarshalAPERTAIListforMDT(v TAIListforMDTComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAIListforWarning encodes a complete named list.
func MarshalAPERTAIListforWarning(v TAIListforWarningComplete, options ...aper.EncodeOption) ([]byte, error) {
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

// MarshalAPERTAListforMDT encodes a complete named list.
func MarshalAPERTAListforMDT(v TAListforMDTComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAListforQMC encodes a complete named list.
func MarshalAPERTAListforQMC(v TAListforQMCComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAIListforQMC encodes a complete named list.
func MarshalAPERTAIListforQMC(v TAIListforQMCComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAIListForRestart encodes a complete named list.
func MarshalAPERTAIListForRestart(v TAIListForRestartComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERUEHistoryInformation encodes a complete named list.
func MarshalAPERUEHistoryInformation(v UEHistoryInformationComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERWLANMeasConfigNameList encodes a complete named list.
func MarshalAPERWLANMeasConfigNameList(v WLANMeasConfigNameListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERTAIListforMDT decodes a complete named list.
func UnmarshalAPERTAIListforMDT(data []byte, options ...aper.DecodeOption) (TAIListforMDTComplete, aper.DecodeReport, error) {
	var v TAIListforMDTComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAIListforWarning decodes a complete named list.
func UnmarshalAPERTAIListforWarning(data []byte, options ...aper.DecodeOption) (TAIListforWarningComplete, aper.DecodeReport, error) {
	var v TAIListforWarningComplete
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

// UnmarshalAPERTAListforMDT decodes a complete named list.
func UnmarshalAPERTAListforMDT(data []byte, options ...aper.DecodeOption) (TAListforMDTComplete, aper.DecodeReport, error) {
	var v TAListforMDTComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAListforQMC decodes a complete named list.
func UnmarshalAPERTAListforQMC(data []byte, options ...aper.DecodeOption) (TAListforQMCComplete, aper.DecodeReport, error) {
	var v TAListforQMCComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAIListforQMC decodes a complete named list.
func UnmarshalAPERTAIListforQMC(data []byte, options ...aper.DecodeOption) (TAIListforQMCComplete, aper.DecodeReport, error) {
	var v TAIListforQMCComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAIListForRestart decodes a complete named list.
func UnmarshalAPERTAIListForRestart(data []byte, options ...aper.DecodeOption) (TAIListForRestartComplete, aper.DecodeReport, error) {
	var v TAIListForRestartComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERUEHistoryInformation decodes a complete named list.
func UnmarshalAPERUEHistoryInformation(data []byte, options ...aper.DecodeOption) (UEHistoryInformationComplete, aper.DecodeReport, error) {
	var v UEHistoryInformationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERWLANMeasConfigNameList decodes a complete named list.
func UnmarshalAPERWLANMeasConfigNameList(data []byte, options ...aper.DecodeOption) (WLANMeasConfigNameListComplete, aper.DecodeReport, error) {
	var v WLANMeasConfigNameListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UplinkNASTransport represents the ASN.1 type UplinkNASTransport (SEQUENCE).
type UplinkNASTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s41.UplinkNASTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ResetAcknowledge represents the ASN.1 type ResetAcknowledge (SEQUENCE).
type ResetAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ResetAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                        `asn1:"-" json:"-"`
	extCount         int64                       `asn1:"-" json:"-"`
	extPresent       []bool                      `asn1:"-" json:"-"`
	extData          [][]byte                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UplinkS1cdma2000tunnelling represents the ASN.1 type UplinkS1cdma2000tunnelling (SEQUENCE).
type UplinkS1cdma2000tunnelling struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s24.UplinkS1cdma2000tunnellingIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
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

// UplinkUEAssociatedLPPaTransport represents the ASN.1 type UplinkUEAssociatedLPPaTransport (SEQUENCE).
type UplinkUEAssociatedLPPaTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s14.UplinkUEAssociatedLPPaTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                           `asn1:"-" json:"-"`
	extCount         int64                                          `asn1:"-" json:"-"`
	extPresent       []bool                                         `asn1:"-" json:"-"`
	extData          [][]byte                                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UplinkNonUEAssociatedLPPaTransport represents the ASN.1 type UplinkNonUEAssociatedLPPaTransport (SEQUENCE).
type UplinkNonUEAssociatedLPPaTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s14.UplinkNonUEAssociatedLPPaTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// TAIListComplete carries a complete TAIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s42.TAIList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s42.BridgeMarshalAPERTAIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIList from APER format.
func (v *TAIListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAIListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIList")
	}
	bb.EnterComponent("TAIList")
	value, err := BridgeUnmarshalAPERTAIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIList")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIList encodes a TAIList list to APER.
func BridgeMarshalAPERTAIList(list TAIListComplete) ([]byte, error) { return list.marshalAPERLegacy() }

// UnmarshalAPERTAIList decodes a TAIList list from APER.
func BridgeUnmarshalAPERTAIList(data []byte) (TAIListComplete, error) {
	var value TAIListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListFrom decodes a TAIList list from bb.
func BridgeUnmarshalAPERTAIListFrom(bb *aper.BitBuffer) (s42.TAIList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s42.BridgeAsn1cAPERTAIListListValue
	if err := BridgeUnmarshalAPERTAIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListInto(v *s42.BridgeAsn1cAPERTAIListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s42.TAIList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s42.TAIItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s42.BridgeTAIItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UplinkNASTransport to APER format.
func (v *UplinkNASTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UplinkNASTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s41.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UplinkNASTransport from APER format.
func (v *UplinkNASTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UplinkNASTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNASTransport")
	}
	bb.EnterComponent("UplinkNASTransport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNASTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "UplinkNASTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "UplinkNASTransport")
	}
	v.perPadding = padding
	return nil
}
func (v *UplinkNASTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkNASTransport{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s41.UplinkNASTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s41.UplinkNASTransportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s41.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// UEAssociatedLogicalS1ConnectionListResComplete carries a complete UEAssociatedLogicalS1ConnectionListRes encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type UEAssociatedLogicalS1ConnectionListResComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s45.UEAssociatedLogicalS1ConnectionListRes
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s45.BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes UEAssociatedLogicalS1ConnectionListRes from APER format.
func (v *UEAssociatedLogicalS1ConnectionListResComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListRes")
	}
	bb.EnterComponent("UEAssociatedLogicalS1ConnectionListRes")
	value, err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListRes")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionListRes")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListRes")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListRes encodes a UEAssociatedLogicalS1ConnectionListRes list to APER.
func BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListRes(list UEAssociatedLogicalS1ConnectionListResComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListRes decodes a UEAssociatedLogicalS1ConnectionListRes list from APER.
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListRes(data []byte) (UEAssociatedLogicalS1ConnectionListResComplete, error) {
	var value UEAssociatedLogicalS1ConnectionListResComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom decodes a UEAssociatedLogicalS1ConnectionListRes list from bb.
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom(bb *aper.BitBuffer) (s45.UEAssociatedLogicalS1ConnectionListRes, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s45.BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResListValue
	if err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResInto(v *s45.BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s45.UEAssociatedLogicalS1ConnectionListRes, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s45.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s45.BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ResetAcknowledge to APER format.
func (v *ResetAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResetAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ResetAcknowledge from APER format.
func (v *ResetAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ResetAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResetAcknowledge")
	}
	bb.EnterComponent("ResetAcknowledge")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResetAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResetAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResetAcknowledge")
	}
	v.perPadding = padding
	return nil
}
func (v *ResetAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResetAcknowledge{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ResetAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ResetAcknowledgeIEField
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

// UEAssociatedLogicalS1ConnectionListResAckComplete carries a complete UEAssociatedLogicalS1ConnectionListResAck encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type UEAssociatedLogicalS1ConnectionListResAckComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s45.UEAssociatedLogicalS1ConnectionListResAck
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s45.BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes UEAssociatedLogicalS1ConnectionListResAck from APER format.
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
	}
	bb.EnterComponent("UEAssociatedLogicalS1ConnectionListResAck")
	value, err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionListResAck")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResAck encodes a UEAssociatedLogicalS1ConnectionListResAck list to APER.
func BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResAck(list UEAssociatedLogicalS1ConnectionListResAckComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck decodes a UEAssociatedLogicalS1ConnectionListResAck list from APER.
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck(data []byte) (UEAssociatedLogicalS1ConnectionListResAckComplete, error) {
	var value UEAssociatedLogicalS1ConnectionListResAckComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom decodes a UEAssociatedLogicalS1ConnectionListResAck list from bb.
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom(bb *aper.BitBuffer) (s45.UEAssociatedLogicalS1ConnectionListResAck, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s45.BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue
	if err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckInto(v *s45.BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s45.UEAssociatedLogicalS1ConnectionListResAck, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s45.UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s45.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UplinkS1cdma2000tunnelling to APER format.
func (v *UplinkS1cdma2000tunnelling) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UplinkS1cdma2000tunnelling from APER format.
func (v *UplinkS1cdma2000tunnelling) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UplinkS1cdma2000tunnelling) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnelling")
	}
	bb.EnterComponent("UplinkS1cdma2000tunnelling")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnelling")
	}
	padding, err := aper.CaptureFinalBits(bb, "UplinkS1cdma2000tunnelling")
	if err != nil {
		return runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnelling")
	}
	v.perPadding = padding
	return nil
}
func (v *UplinkS1cdma2000tunnelling) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkS1cdma2000tunnelling{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s24.UplinkS1cdma2000tunnellingIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s24.UplinkS1cdma2000tunnellingIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// UnmarshalAPER decodes PWSRestartIndication from APER format.
func (v *PWSRestartIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *PWSRestartIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PWSRestartIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(PWSRestartIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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

// MarshalAPER encodes UplinkUEAssociatedLPPaTransport to APER format.
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UplinkUEAssociatedLPPaTransport from APER format.
func (v *UplinkUEAssociatedLPPaTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UplinkUEAssociatedLPPaTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransport")
	}
	bb.EnterComponent("UplinkUEAssociatedLPPaTransport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "UplinkUEAssociatedLPPaTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransport")
	}
	v.perPadding = padding
	return nil
}
func (v *UplinkUEAssociatedLPPaTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkUEAssociatedLPPaTransport{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s14.UplinkUEAssociatedLPPaTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s14.UplinkUEAssociatedLPPaTransportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UplinkNonUEAssociatedLPPaTransport to APER format.
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UplinkNonUEAssociatedLPPaTransport from APER format.
func (v *UplinkNonUEAssociatedLPPaTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UplinkNonUEAssociatedLPPaTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	bb.EnterComponent("UplinkNonUEAssociatedLPPaTransport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "UplinkNonUEAssociatedLPPaTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	v.perPadding = padding
	return nil
}
func (v *UplinkNonUEAssociatedLPPaTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkNonUEAssociatedLPPaTransport{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s14.UplinkNonUEAssociatedLPPaTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s14.UplinkNonUEAssociatedLPPaTransportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s14.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *PWSRestartIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "PWSRestartIndication", v.receivedLocation, v.perPadding)
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
func (v *ResetAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResetAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ResetAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResetAcknowledge) WithoutReplay() ResetAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ResetAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListComplete) WithoutReplay() TAIListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionListResAckComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionListResAckComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEAssociatedLogicalS1ConnectionListResAckComplete) WithoutReplay() UEAssociatedLogicalS1ConnectionListResAckComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEAssociatedLogicalS1ConnectionListResAckComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEAssociatedLogicalS1ConnectionListResComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionListResComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionListResComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEAssociatedLogicalS1ConnectionListResComplete) WithoutReplay() UEAssociatedLogicalS1ConnectionListResComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEAssociatedLogicalS1ConnectionListResComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UplinkNASTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UplinkNASTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UplinkNASTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UplinkNASTransport) WithoutReplay() UplinkNASTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UplinkNASTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UplinkNonUEAssociatedLPPaTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UplinkNonUEAssociatedLPPaTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UplinkNonUEAssociatedLPPaTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UplinkNonUEAssociatedLPPaTransport) WithoutReplay() UplinkNonUEAssociatedLPPaTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UplinkNonUEAssociatedLPPaTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UplinkS1cdma2000tunnelling) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UplinkS1cdma2000tunnelling", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UplinkS1cdma2000tunnelling", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UplinkS1cdma2000tunnelling) WithoutReplay() UplinkS1cdma2000tunnelling {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UplinkS1cdma2000tunnelling
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UplinkUEAssociatedLPPaTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UplinkUEAssociatedLPPaTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UplinkUEAssociatedLPPaTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UplinkUEAssociatedLPPaTransport) WithoutReplay() UplinkUEAssociatedLPPaTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UplinkUEAssociatedLPPaTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
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
func (v *ResetAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResetAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResetAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResetAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResetAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResetAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResetAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UplinkNASTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UplinkNASTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkNASTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkNASTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UplinkNASTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkNASTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkNASTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UplinkNonUEAssociatedLPPaTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UplinkNonUEAssociatedLPPaTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UplinkNonUEAssociatedLPPaTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UplinkS1cdma2000tunnelling) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UplinkS1cdma2000tunnelling) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UplinkS1cdma2000tunnelling) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UplinkUEAssociatedLPPaTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UplinkUEAssociatedLPPaTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UplinkUEAssociatedLPPaTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
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
func (v *ResetAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ResetAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ResetAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResetAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APResetAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ResetAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ResetAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ResetAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ResetAcknowledge")
}
func (v *ResetAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ResetAcknowledge")
}
func (v *ResetAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APResetAcknowledge(v, &s)
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
func (v *ResetAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ResetAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAIListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListComplete")
}
func (v *TAIListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListComplete")
}
func (v *TAIListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListComplete(v, &s)
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
func (v *TAIListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s42.BridgeMarshalAPERTAIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionListResAckComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAckComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEAssociatedLogicalS1ConnectionListResAckComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAckComplete(v, &s)
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
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s45.BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEAssociatedLogicalS1ConnectionListResComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionListResComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEAssociatedLogicalS1ConnectionListResComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResComplete(v, &s)
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
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s45.BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UplinkNASTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UplinkNASTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UplinkNASTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UplinkNASTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUplinkNASTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UplinkNASTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UplinkNASTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UplinkNASTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UplinkNASTransport")
}
func (v *UplinkNASTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UplinkNASTransport")
}
func (v *UplinkNASTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUplinkNASTransport(v, &s)
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
func (v *UplinkNASTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UplinkNASTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UplinkNonUEAssociatedLPPaTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UplinkNonUEAssociatedLPPaTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UplinkNonUEAssociatedLPPaTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(v, &s)
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
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UplinkS1cdma2000tunnelling) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UplinkS1cdma2000tunnelling")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUplinkS1cdma2000tunnelling(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UplinkS1cdma2000tunnelling")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUplinkS1cdma2000tunnelling(v, &s)
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
func (v *UplinkS1cdma2000tunnelling) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UplinkUEAssociatedLPPaTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UplinkUEAssociatedLPPaTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUplinkUEAssociatedLPPaTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UplinkUEAssociatedLPPaTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUplinkUEAssociatedLPPaTransport(v, &s)
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
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ResetAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResetAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ResetAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APResetAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ResetAcknowledge{}
		return report, aper.OperationError(err, "ResetAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResetAcknowledge")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListComplete{}
		return report, aper.OperationError(err, "TAIListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionListResAckComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEAssociatedLogicalS1ConnectionListResAckComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAckComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEAssociatedLogicalS1ConnectionListResAckComplete{}
		return report, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEAssociatedLogicalS1ConnectionListResAckComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEAssociatedLogicalS1ConnectionListResComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionListResComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEAssociatedLogicalS1ConnectionListResComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEAssociatedLogicalS1ConnectionListResComplete{}
		return report, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEAssociatedLogicalS1ConnectionListResComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UplinkNASTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UplinkNASTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UplinkNASTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUplinkNASTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UplinkNASTransport{}
		return report, aper.OperationError(err, "UplinkNASTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UplinkNASTransport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UplinkNonUEAssociatedLPPaTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UplinkNonUEAssociatedLPPaTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UplinkNonUEAssociatedLPPaTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUplinkNonUEAssociatedLPPaTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UplinkNonUEAssociatedLPPaTransport{}
		return report, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UplinkNonUEAssociatedLPPaTransport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UplinkS1cdma2000tunnelling) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UplinkS1cdma2000tunnelling")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UplinkS1cdma2000tunnelling
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUplinkS1cdma2000tunnelling(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UplinkS1cdma2000tunnelling{}
		return report, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UplinkS1cdma2000tunnelling")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UplinkUEAssociatedLPPaTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UplinkUEAssociatedLPPaTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UplinkUEAssociatedLPPaTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUplinkUEAssociatedLPPaTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UplinkUEAssociatedLPPaTransport{}
		return report, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UplinkUEAssociatedLPPaTransport")
}

// MarshalAPERTAIList encodes a complete named list.
func MarshalAPERTAIList(v TAIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListRes encodes a complete named list.
func MarshalAPERUEAssociatedLogicalS1ConnectionListRes(v UEAssociatedLogicalS1ConnectionListResComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResAck encodes a complete named list.
func MarshalAPERUEAssociatedLogicalS1ConnectionListResAck(v UEAssociatedLogicalS1ConnectionListResAckComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERTAIList decodes a complete named list.
func UnmarshalAPERTAIList(data []byte, options ...aper.DecodeOption) (TAIListComplete, aper.DecodeReport, error) {
	var v TAIListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListRes decodes a complete named list.
func UnmarshalAPERUEAssociatedLogicalS1ConnectionListRes(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionListResComplete, aper.DecodeReport, error) {
	var v UEAssociatedLogicalS1ConnectionListResComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck decodes a complete named list.
func UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionListResAckComplete, aper.DecodeReport, error) {
	var v UEAssociatedLogicalS1ConnectionListResAckComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type PWSRestartIndicationIEValue struct {
	id                               s00.ProtocolIEID
	received                         aper.WireSpan
	replay                           aper.Snapshot
	opaque                           aper.OpaqueOpenType
	isOpaque                         bool
	rowECGIListForRestart            *s20.ECGIListForRestart
	rowGlobalENBID                   *s21.GlobalENBID
	rowTAIListForRestart             *s41.TAIListForRestart
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
func (v *PWSRestartIndicationIEValue) AsECGIListForRestart() (*s20.ECGIListForRestart, bool) {
	if v == nil || v.id != s00.ProtocolIEID(182) || v.rowECGIListForRestart == nil {
		return nil, false
	}
	return v.rowECGIListForRestart, true
}

// AsGlobalENBID returns the selected GlobalENBID value of PWSRestartIndicationIEValue and reports whether that alternative is active.
func (v *PWSRestartIndicationIEValue) AsGlobalENBID() (*s21.GlobalENBID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(59) || v.rowGlobalENBID == nil {
		return nil, false
	}
	return v.rowGlobalENBID, true
}

// AsTAIListForRestart returns the selected TAIListForRestart value of PWSRestartIndicationIEValue and reports whether that alternative is active.
func (v *PWSRestartIndicationIEValue) AsTAIListForRestart() (*s41.TAIListForRestart, bool) {
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
		list, err := s48.BridgeUnmarshalAPERECGIListForRestartFrom(child)
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
		list, err := s51.BridgeUnmarshalAPEREmergencyAreaIDListForRestartFrom(child)
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
		complete := s48.ECGIListForRestartComplete{Value: *v.rowECGIListForRestart}
		candidate, err := s48.BridgeECGIListForRestartCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
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
		candidate, err := s21.BridgeGlobalENBIDMethodMarshalAPERBudget(v.rowGlobalENBID, budget, fresh)
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
		complete := s51.EmergencyAreaIDListForRestartComplete{Value: *v.rowEmergencyAreaIDListForRestart}
		candidate, err := s51.BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PWSRestartIndicationIEValue:", v.id)
	}
}

type ResetAcknowledgeIEValue struct {
	id                                           s00.ProtocolIEID
	received                                     aper.WireSpan
	replay                                       aper.Snapshot
	opaque                                       aper.OpaqueOpenType
	isOpaque                                     bool
	rowUEAssociatedLogicalS1ConnectionListResAck *s45.UEAssociatedLogicalS1ConnectionListResAck
	rowCriticalityDiagnostics                    *s26.CriticalityDiagnostics
}

func (v ResetAcknowledgeIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(93):
		return v.rowUEAssociatedLogicalS1ConnectionListResAck != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ResetAcknowledgeIEValue and reports whether the opaque alternative is selected.
func (v *ResetAcknowledgeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ResetAcknowledgeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetAcknowledgeIEs"}}
}
func (ResetAcknowledgeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(93):
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

// AsUEAssociatedLogicalS1ConnectionListResAck returns the selected UEAssociatedLogicalS1ConnectionListResAck value of ResetAcknowledgeIEValue and reports whether that alternative is active.
func (v *ResetAcknowledgeIEValue) AsUEAssociatedLogicalS1ConnectionListResAck() (*s45.UEAssociatedLogicalS1ConnectionListResAck, bool) {
	if v == nil || v.id != s00.ProtocolIEID(93) || v.rowUEAssociatedLogicalS1ConnectionListResAck == nil {
		return nil, false
	}
	return v.rowUEAssociatedLogicalS1ConnectionListResAck, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of ResetAcknowledgeIEValue and reports whether that alternative is active.
func (v *ResetAcknowledgeIEValue) AsCriticalityDiagnostics() (*s26.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v ResetAcknowledgeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResetAcknowledgeIEValue, error) {
	out := ResetAcknowledgeIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(93):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UEAssociatedLogicalS1ConnectionListResAck:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowUEAssociatedLogicalS1ConnectionListResAck = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v ResetAcknowledgeIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ResetAcknowledgeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(93):
		if v.rowUEAssociatedLogicalS1ConnectionListResAck == nil {
			return nil, fmt.Errorf("%s missing value", "ResetAcknowledgeIEs.id-UE-associatedLogicalS1-ConnectionListResAck:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := UEAssociatedLogicalS1ConnectionListResAckComplete{Value: *v.rowUEAssociatedLogicalS1ConnectionListResAck}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "ResetAcknowledgeIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResetAcknowledgeIEValue:", v.id)
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
	return PWSRestartIndicationECGIListForRestartIEBinding{info: t.infoECGIListForRestart(), codec: func() s20.ECGIListForRestartValueCodec {
		sealed := s20.ECGIListForRestartValueCodec{}
		*s20.BridgeECGIListForRestartValueCodecFieldPath(&sealed) = "ECGIListForRestart"
		*s20.BridgeECGIListForRestartValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ECGIListForRestart, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.ECGIListForRestart
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ECGIListForRestart")
			var zero PWSRestartIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(182), raw)
			if err != nil {
				var empty s20.ECGIListForRestart
				return empty, runtime.WrapDecodePath(err, "ECGIListForRestart")
			}
			value, ok := decoded.AsECGIListForRestart()
			if !ok {
				var empty s20.ECGIListForRestart
				return empty, fmt.Errorf("binding PWSRestartIndicationIEs.id-ECGIListForRestart: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeECGIListForRestartValueCodecFieldEncode(&sealed) = func(value s20.ECGIListForRestart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSRestartIndicationIEValue{id: s00.ProtocolIEID(182), rowECGIListForRestart: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeECGIListForRestartValueCodecFieldCapture(&sealed) = func(v s20.ECGIListForRestart, options aper.DecodeState) (s20.ECGIListForRestart, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APECGIListForRestart(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s20.BridgeECGIListForRestartValueCodecFieldCompare(&sealed) = func(v s20.ECGIListForRestart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APECGIListForRestart(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeECGIListForRestartValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECGIListForRestart"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.ECGIListForRestart) PWSRestartIndicationIEValue {
			return PWSRestartIndicationIEValue{id: s00.ProtocolIEID(182), rowECGIListForRestart: &value}
		}, get: func(value *PWSRestartIndicationIEValue) (*s20.ECGIListForRestart, bool) {
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
	return PWSRestartIndicationGlobalENBIDIEBinding{info: t.infoGlobalENBID(), codec: func() s21.GlobalENBIDValueCodec {
		sealed := s21.GlobalENBIDValueCodec{}
		*s21.BridgeGlobalENBIDValueCodecFieldPath(&sealed) = "GlobalENBID"
		*s21.BridgeGlobalENBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.GlobalENBID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s21.GlobalENBID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GlobalENBID")
			var zero PWSRestartIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(59), raw)
			if err != nil {
				var empty s21.GlobalENBID
				return empty, runtime.WrapDecodePath(err, "GlobalENBID")
			}
			value, ok := decoded.AsGlobalENBID()
			if !ok {
				var empty s21.GlobalENBID
				return empty, fmt.Errorf("binding PWSRestartIndicationIEs.id-Global-ENB-ID: no selected value")
			}
			return *value, nil
		}
		*s21.BridgeGlobalENBIDValueCodecFieldEncode(&sealed) = func(value s21.GlobalENBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSRestartIndicationIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s21.GlobalENBID) PWSRestartIndicationIEValue {
			return PWSRestartIndicationIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}
		}, get: func(value *PWSRestartIndicationIEValue) (*s21.GlobalENBID, bool) { return value.AsGlobalENBID() }}
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
	return PWSRestartIndicationTAIListForRestartIEBinding{info: t.infoTAIListForRestart(), codec: func() s41.TAIListForRestartValueCodec {
		sealed := s41.TAIListForRestartValueCodec{}
		*s41.BridgeTAIListForRestartValueCodecFieldPath(&sealed) = "TAIListForRestart"
		*s41.BridgeTAIListForRestartValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.TAIListForRestart, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s41.TAIListForRestart
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAIListForRestart")
			var zero PWSRestartIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(188), raw)
			if err != nil {
				var empty s41.TAIListForRestart
				return empty, runtime.WrapDecodePath(err, "TAIListForRestart")
			}
			value, ok := decoded.AsTAIListForRestart()
			if !ok {
				var empty s41.TAIListForRestart
				return empty, fmt.Errorf("binding PWSRestartIndicationIEs.id-TAIListForRestart: no selected value")
			}
			return *value, nil
		}
		*s41.BridgeTAIListForRestartValueCodecFieldEncode(&sealed) = func(value s41.TAIListForRestart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSRestartIndicationIEValue{id: s00.ProtocolIEID(188), rowTAIListForRestart: &value}).encodeFresh(fresh, budget)
		}
		*s41.BridgeTAIListForRestartValueCodecFieldCapture(&sealed) = func(v s41.TAIListForRestart, options aper.DecodeState) (s41.TAIListForRestart, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s41.BridgeCaptureS1APTAIListForRestart(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s41.BridgeTAIListForRestartValueCodecFieldCompare(&sealed) = func(v s41.TAIListForRestart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s41.BridgeCompareS1APTAIListForRestart(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s41.BridgeTAIListForRestartValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIListForRestart"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s41.TAIListForRestart) PWSRestartIndicationIEValue {
			return PWSRestartIndicationIEValue{id: s00.ProtocolIEID(188), rowTAIListForRestart: &value}
		}, get: func(value *PWSRestartIndicationIEValue) (*s41.TAIListForRestart, bool) {
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

type ResetAcknowledgeIETable struct{}

func ResetAcknowledgeIEs() ResetAcknowledgeIETable { return ResetAcknowledgeIETable{} }

// ID returns the ASN.1 object-set identity of ResetAcknowledgeIETable.
func (ResetAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ResetAcknowledgeIETable.
func (ResetAcknowledgeIETable) Table() s00.ResetAcknowledgeIEValueIETable {
	return func() s00.ResetAcknowledgeIEValueIETable {
		sealed := s00.ResetAcknowledgeIEValueIETable{}
		*s00.BridgeResetAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ResetAcknowledgeIETable) infoUEAssociatedLogicalS1ConnectionListResAck() s00.FieldInfo {
	return s00.FieldInfo{Table: ResetAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(93), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionListResAck"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetAcknowledgeIEs", Row: "id-UE-associatedLogicalS1-ConnectionListResAck"}}}
}

// UEAssociatedLogicalS1ConnectionListResAck returns the typed binding for the UEAssociatedLogicalS1ConnectionListResAck row of ResetAcknowledgeIETable.
func (t ResetAcknowledgeIETable) UEAssociatedLogicalS1ConnectionListResAck() ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding {
	return ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding{info: t.infoUEAssociatedLogicalS1ConnectionListResAck(), codec: func() s45.UEAssociatedLogicalS1ConnectionListResAckValueCodec {
		sealed := s45.UEAssociatedLogicalS1ConnectionListResAckValueCodec{}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldPath(&sealed) = "UEAssociatedLogicalS1ConnectionListResAck"
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEAssociatedLogicalS1ConnectionListResAck, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s45.UEAssociatedLogicalS1ConnectionListResAck
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAssociatedLogicalS1ConnectionListResAck")
			var zero ResetAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(93), raw)
			if err != nil {
				var empty s45.UEAssociatedLogicalS1ConnectionListResAck
				return empty, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
			}
			value, ok := decoded.AsUEAssociatedLogicalS1ConnectionListResAck()
			if !ok {
				var empty s45.UEAssociatedLogicalS1ConnectionListResAck
				return empty, fmt.Errorf("binding ResetAcknowledgeIEs.id-UE-associatedLogicalS1-ConnectionListResAck: no selected value")
			}
			return *value, nil
		}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldEncode(&sealed) = func(value s45.UEAssociatedLogicalS1ConnectionListResAck, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResetAcknowledgeIEValue{id: s00.ProtocolIEID(93), rowUEAssociatedLogicalS1ConnectionListResAck: &value}).encodeFresh(fresh, budget)
		}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldCapture(&sealed) = func(v s45.UEAssociatedLogicalS1ConnectionListResAck, options aper.DecodeState) (s45.UEAssociatedLogicalS1ConnectionListResAck, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAck(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldCompare(&sealed) = func(v s45.UEAssociatedLogicalS1ConnectionListResAck, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			s45.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAck(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAssociatedLogicalS1ConnectionListResAck"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s45.UEAssociatedLogicalS1ConnectionListResAck) ResetAcknowledgeIEValue {
			return ResetAcknowledgeIEValue{id: s00.ProtocolIEID(93), rowUEAssociatedLogicalS1ConnectionListResAck: &value}
		}, get: func(value *ResetAcknowledgeIEValue) (*s45.UEAssociatedLogicalS1ConnectionListResAck, bool) {
			return value.AsUEAssociatedLogicalS1ConnectionListResAck()
		}}
}
func (ResetAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ResetAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ResetAcknowledgeIETable.
func (t ResetAcknowledgeIETable) CriticalityDiagnostics() ResetAcknowledgeCriticalityDiagnosticsIEBinding {
	return ResetAcknowledgeCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s26.CriticalityDiagnosticsValueCodec {
		sealed := s26.CriticalityDiagnosticsValueCodec{}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ResetAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s26.CriticalityDiagnostics
				return empty, fmt.Errorf("binding ResetAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResetAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s26.CriticalityDiagnostics) ResetAcknowledgeIEValue {
			return ResetAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *ResetAcknowledgeIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ResetAcknowledgeIETable.
func (t ResetAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResetAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(93):
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-associatedLogicalS1-ConnectionListResAck requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResetAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResetAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return ResetAcknowledgeIEField{Id: id, Criticality: criticality, Value: ResetAcknowledgeIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ECGIListForRestartCodec binds the complete APER value type.
func ECGIListForRestartCodec() s20.ECGIListForRestartValueCodec {
	return PWSRestartIndicationIEs().ECGIListForRestart().Codec()
}

// EmergencyAreaIDListForRestartCodec binds the complete APER value type.
func EmergencyAreaIDListForRestartCodec() s00.EmergencyAreaIDListForRestartValueCodec {
	return PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Codec()
}

// TAIBroadcastCodec binds the complete source value type.
func TAIBroadcastCodec() s41.TAIBroadcastValueCodec {
	return func() s41.TAIBroadcastValueCodec {
		sealed := s41.TAIBroadcastValueCodec{}
		*s41.BridgeTAIBroadcastValueCodecFieldPath(&sealed) = "TAIBroadcast"
		*s41.BridgeTAIBroadcastValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.TAIBroadcast, error) {
			var complete TAIBroadcastComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s41.TAIBroadcast
				return zero, err
			}
			return complete.Value, nil
		}
		*s41.BridgeTAIBroadcastValueCodecFieldEncode(&sealed) = func(value s41.TAIBroadcast, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAIBroadcastComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s41.BridgeTAIBroadcastValueCodecFieldCapture(&sealed) = func(v s41.TAIBroadcast, options aper.DecodeState) (s41.TAIBroadcast, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s41.BridgeCaptureS1APTAIBroadcast(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeTAIBroadcastValueCodecFieldCompare(&sealed) = func(v s41.TAIBroadcast, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s41.BridgeCompareS1APTAIBroadcast(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s41.BridgeTAIBroadcastValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIBroadcast"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAICancelledCodec binds the complete source value type.
func TAICancelledCodec() s41.TAICancelledValueCodec {
	return func() s41.TAICancelledValueCodec {
		sealed := s41.TAICancelledValueCodec{}
		*s41.BridgeTAICancelledValueCodecFieldPath(&sealed) = "TAICancelled"
		*s41.BridgeTAICancelledValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.TAICancelled, error) {
			var complete TAICancelledComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s41.TAICancelled
				return zero, err
			}
			return complete.Value, nil
		}
		*s41.BridgeTAICancelledValueCodecFieldEncode(&sealed) = func(value s41.TAICancelled, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAICancelledComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s41.BridgeTAICancelledValueCodecFieldCapture(&sealed) = func(v s41.TAICancelled, options aper.DecodeState) (s41.TAICancelled, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s41.BridgeCaptureS1APTAICancelled(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeTAICancelledValueCodecFieldCompare(&sealed) = func(v s41.TAICancelled, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s41.BridgeCompareS1APTAICancelled(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s41.BridgeTAICancelledValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAICancelled"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIListForRestartCodec binds the complete APER value type.
func TAIListForRestartCodec() s41.TAIListForRestartValueCodec {
	return PWSRestartIndicationIEs().TAIListForRestart().Codec()
}

// TAIListforMDTCodec binds the complete source value type.
func TAIListforMDTCodec() s41.TAIListforMDTValueCodec {
	return func() s41.TAIListforMDTValueCodec {
		sealed := s41.TAIListforMDTValueCodec{}
		*s41.BridgeTAIListforMDTValueCodecFieldPath(&sealed) = "TAIListforMDT"
		*s41.BridgeTAIListforMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.TAIListforMDT, error) {
			var complete TAIListforMDTComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s41.TAIListforMDT
				return zero, err
			}
			return complete.Value, nil
		}
		*s41.BridgeTAIListforMDTValueCodecFieldEncode(&sealed) = func(value s41.TAIListforMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAIListforMDTComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s41.BridgeTAIListforMDTValueCodecFieldCapture(&sealed) = func(v s41.TAIListforMDT, options aper.DecodeState) (s41.TAIListforMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s41.BridgeCaptureS1APTAIListforMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeTAIListforMDTValueCodecFieldCompare(&sealed) = func(v s41.TAIListforMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s41.BridgeCompareS1APTAIListforMDT(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s41.BridgeTAIListforMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIListforMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIListforQMCCodec binds the complete source value type.
func TAIListforQMCCodec() s41.TAIListforQMCValueCodec {
	return func() s41.TAIListforQMCValueCodec {
		sealed := s41.TAIListforQMCValueCodec{}
		*s41.BridgeTAIListforQMCValueCodecFieldPath(&sealed) = "TAIListforQMC"
		*s41.BridgeTAIListforQMCValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.TAIListforQMC, error) {
			var complete TAIListforQMCComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s41.TAIListforQMC
				return zero, err
			}
			return complete.Value, nil
		}
		*s41.BridgeTAIListforQMCValueCodecFieldEncode(&sealed) = func(value s41.TAIListforQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAIListforQMCComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s41.BridgeTAIListforQMCValueCodecFieldCapture(&sealed) = func(v s41.TAIListforQMC, options aper.DecodeState) (s41.TAIListforQMC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s41.BridgeCaptureS1APTAIListforQMC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeTAIListforQMCValueCodecFieldCompare(&sealed) = func(v s41.TAIListforQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s41.BridgeCompareS1APTAIListforQMC(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s41.BridgeTAIListforQMCValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIListforQMC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIListforWarningCodec binds the complete source value type.
func TAIListforWarningCodec() s41.TAIListforWarningValueCodec {
	return func() s41.TAIListforWarningValueCodec {
		sealed := s41.TAIListforWarningValueCodec{}
		*s41.BridgeTAIListforWarningValueCodecFieldPath(&sealed) = "TAIListforWarning"
		*s41.BridgeTAIListforWarningValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.TAIListforWarning, error) {
			var complete TAIListforWarningComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s41.TAIListforWarning
				return zero, err
			}
			return complete.Value, nil
		}
		*s41.BridgeTAIListforWarningValueCodecFieldEncode(&sealed) = func(value s41.TAIListforWarning, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAIListforWarningComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s41.BridgeTAIListforWarningValueCodecFieldCapture(&sealed) = func(v s41.TAIListforWarning, options aper.DecodeState) (s41.TAIListforWarning, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s41.BridgeCaptureS1APTAIListforWarning(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s41.BridgeTAIListforWarningValueCodecFieldCompare(&sealed) = func(v s41.TAIListforWarning, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s41.BridgeCompareS1APTAIListforWarning(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s41.BridgeTAIListforWarningValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIListforWarning"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAListforMDTCodec binds the complete source value type.
func TAListforMDTCodec() s02.TAListforMDTValueCodec {
	return func() s02.TAListforMDTValueCodec {
		sealed := s02.TAListforMDTValueCodec{}
		*s02.BridgeTAListforMDTValueCodecFieldPath(&sealed) = "TAListforMDT"
		*s02.BridgeTAListforMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TAListforMDT, error) {
			var complete TAListforMDTComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.TAListforMDT
				return zero, err
			}
			return complete.Value, nil
		}
		*s02.BridgeTAListforMDTValueCodecFieldEncode(&sealed) = func(value s00.TAListforMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAListforMDTComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s02.BridgeTAListforMDTValueCodecFieldCapture(&sealed) = func(v s00.TAListforMDT, options aper.DecodeState) (s00.TAListforMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTAListforMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTAListforMDTValueCodecFieldCompare(&sealed) = func(v s00.TAListforMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APTAListforMDT(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s02.BridgeTAListforMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAListforMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAListforQMCCodec binds the complete source value type.
func TAListforQMCCodec() s02.TAListforQMCValueCodec {
	return func() s02.TAListforQMCValueCodec {
		sealed := s02.TAListforQMCValueCodec{}
		*s02.BridgeTAListforQMCValueCodecFieldPath(&sealed) = "TAListforQMC"
		*s02.BridgeTAListforQMCValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TAListforQMC, error) {
			var complete TAListforQMCComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.TAListforQMC
				return zero, err
			}
			return complete.Value, nil
		}
		*s02.BridgeTAListforQMCValueCodecFieldEncode(&sealed) = func(value s00.TAListforQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAListforQMCComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s02.BridgeTAListforQMCValueCodecFieldCapture(&sealed) = func(v s00.TAListforQMC, options aper.DecodeState) (s00.TAListforQMC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTAListforQMC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTAListforQMCValueCodecFieldCompare(&sealed) = func(v s00.TAListforQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APTAListforQMC(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s02.BridgeTAListforQMCValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAListforQMC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEAssociatedLogicalS1ConnectionListResAckCodec binds the complete APER value type.
func UEAssociatedLogicalS1ConnectionListResAckCodec() s45.UEAssociatedLogicalS1ConnectionListResAckValueCodec {
	return ResetAcknowledgeIEs().UEAssociatedLogicalS1ConnectionListResAck().Codec()
}

// UEAssociatedLogicalS1ConnectionListResCodec binds the complete source value type.
func UEAssociatedLogicalS1ConnectionListResCodec() s45.UEAssociatedLogicalS1ConnectionListResValueCodec {
	return func() s45.UEAssociatedLogicalS1ConnectionListResValueCodec {
		sealed := s45.UEAssociatedLogicalS1ConnectionListResValueCodec{}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldPath(&sealed) = "UEAssociatedLogicalS1ConnectionListRes"
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEAssociatedLogicalS1ConnectionListRes, error) {
			var complete UEAssociatedLogicalS1ConnectionListResComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s45.UEAssociatedLogicalS1ConnectionListRes
				return zero, err
			}
			return complete.Value, nil
		}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldEncode(&sealed) = func(value s45.UEAssociatedLogicalS1ConnectionListRes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := UEAssociatedLogicalS1ConnectionListResComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldCapture(&sealed) = func(v s45.UEAssociatedLogicalS1ConnectionListRes, options aper.DecodeState) (s45.UEAssociatedLogicalS1ConnectionListRes, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListRes(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldCompare(&sealed) = func(v s45.UEAssociatedLogicalS1ConnectionListRes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s45.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListRes(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s45.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAssociatedLogicalS1ConnectionListRes"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEHistoryInformationCodec binds the complete source value type.
func UEHistoryInformationCodec() s52.UEHistoryInformationValueCodec {
	return func() s52.UEHistoryInformationValueCodec {
		sealed := s52.UEHistoryInformationValueCodec{}
		*s52.BridgeUEHistoryInformationValueCodecFieldPath(&sealed) = "UEHistoryInformation"
		*s52.BridgeUEHistoryInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s52.UEHistoryInformation, error) {
			var complete UEHistoryInformationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s52.UEHistoryInformation
				return zero, err
			}
			return complete.Value, nil
		}
		*s52.BridgeUEHistoryInformationValueCodecFieldEncode(&sealed) = func(value s52.UEHistoryInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := UEHistoryInformationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s52.BridgeUEHistoryInformationValueCodecFieldCapture(&sealed) = func(v s52.UEHistoryInformation, options aper.DecodeState) (s52.UEHistoryInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s52.BridgeCaptureS1APUEHistoryInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s52.BridgeUEHistoryInformationValueCodecFieldCompare(&sealed) = func(v s52.UEHistoryInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s52.BridgeCompareS1APUEHistoryInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s52.BridgeUEHistoryInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEHistoryInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WLANMeasConfigNameListCodec binds the complete source value type.
func WLANMeasConfigNameListCodec() s02.WLANMeasConfigNameListValueCodec {
	return func() s02.WLANMeasConfigNameListValueCodec {
		sealed := s02.WLANMeasConfigNameListValueCodec{}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldPath(&sealed) = "WLANMeasConfigNameList"
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANMeasConfigNameList, error) {
			var complete WLANMeasConfigNameListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.WLANMeasConfigNameList
				return zero, err
			}
			return complete.Value, nil
		}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldEncode(&sealed) = func(value s00.WLANMeasConfigNameList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := WLANMeasConfigNameListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldCapture(&sealed) = func(v s00.WLANMeasConfigNameList, options aper.DecodeState) (s00.WLANMeasConfigNameList, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APWLANMeasConfigNameList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldCompare(&sealed) = func(v s00.WLANMeasConfigNameList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APWLANMeasConfigNameList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasConfigNameList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BridgePWSRestartIndicationFieldPerPadding(v *PWSRestartIndication) *aper.FinalPadding {
	return &v.perPadding
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
func BridgePWSRestartIndicationIEValueFieldId(v *PWSRestartIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePWSRestartIndicationIEValueFieldIsOpaque(v *PWSRestartIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgePWSRestartIndicationIEValueFieldOpaque(v *PWSRestartIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePWSRestartIndicationIEValueFieldRowECGIListForRestart(v *PWSRestartIndicationIEValue) **s20.ECGIListForRestart {
	return &v.rowECGIListForRestart
}
func BridgePWSRestartIndicationIEValueFieldRowEmergencyAreaIDListForRestart(v *PWSRestartIndicationIEValue) **s00.EmergencyAreaIDListForRestart {
	return &v.rowEmergencyAreaIDListForRestart
}
func BridgePWSRestartIndicationIEValueFieldRowGlobalENBID(v *PWSRestartIndicationIEValue) **s21.GlobalENBID {
	return &v.rowGlobalENBID
}
func BridgePWSRestartIndicationIEValueFieldRowTAIListForRestart(v *PWSRestartIndicationIEValue) **s41.TAIListForRestart {
	return &v.rowTAIListForRestart
}
func BridgePWSRestartIndicationMethodMarshalAPERBudget(v *PWSRestartIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePWSRestartIndicationMethodUnmarshalAPERFrom(v *PWSRestartIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePWSRestartIndicationMethodUnmarshalAPERWithOptions(v *PWSRestartIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func BridgeResetAcknowledgeFieldPerPadding(v *ResetAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeResetAcknowledgeFieldReceived(v *ResetAcknowledge) *bool { return &v.received }
func BridgeResetAcknowledgeFieldReceivedAbsolute(v *ResetAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgeResetAcknowledgeFieldReceivedBytes(v *ResetAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResetAcknowledgeFieldReceivedLocation(v *ResetAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgeResetAcknowledgeIEValueFieldId(v *ResetAcknowledgeIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeResetAcknowledgeIEValueFieldIsOpaque(v *ResetAcknowledgeIEValue) *bool       { return &v.isOpaque }
func BridgeResetAcknowledgeIEValueFieldOpaque(v *ResetAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeResetAcknowledgeIEValueFieldRowCriticalityDiagnostics(v *ResetAcknowledgeIEValue) **s26.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeResetAcknowledgeIEValueFieldRowUEAssociatedLogicalS1ConnectionListResAck(v *ResetAcknowledgeIEValue) **s45.UEAssociatedLogicalS1ConnectionListResAck {
	return &v.rowUEAssociatedLogicalS1ConnectionListResAck
}
func BridgeResetAcknowledgeMethodMarshalAPERBudget(v *ResetAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResetAcknowledgeMethodUnmarshalAPERFrom(v *ResetAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResetAcknowledgeMethodUnmarshalAPERWithOptions(v *ResetAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResetAcknowledgeValueCodecFieldCapture(v *ResetAcknowledgeValueCodec) *func(ResetAcknowledge, aper.DecodeState) (ResetAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeValueCodecFieldCompare(v *ResetAcknowledgeValueCodec) *func(ResetAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeValueCodecFieldContext(v *ResetAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeValueCodecFieldDecode(v *ResetAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (ResetAcknowledge, error) {
	return &v.decode
}
func BridgeResetAcknowledgeValueCodecFieldEncode(v *ResetAcknowledgeValueCodec) *func(ResetAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeValueCodecFieldPath(v *ResetAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIListCompleteMethodMarshalAPERBudget(v *TAIListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkNASTransportFieldPerPadding(v *UplinkNASTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUplinkNASTransportFieldReceived(v *UplinkNASTransport) *bool { return &v.received }
func BridgeUplinkNASTransportFieldReceivedAbsolute(v *UplinkNASTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeUplinkNASTransportFieldReceivedBytes(v *UplinkNASTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUplinkNASTransportFieldReceivedLocation(v *UplinkNASTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeUplinkNASTransportMethodMarshalAPERBudget(v *UplinkNASTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkNASTransportMethodUnmarshalAPERFrom(v *UplinkNASTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkNASTransportMethodUnmarshalAPERWithOptions(v *UplinkNASTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkNASTransportValueCodecFieldCapture(v *UplinkNASTransportValueCodec) *func(UplinkNASTransport, aper.DecodeState) (UplinkNASTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportValueCodecFieldCompare(v *UplinkNASTransportValueCodec) *func(UplinkNASTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportValueCodecFieldContext(v *UplinkNASTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportValueCodecFieldDecode(v *UplinkNASTransportValueCodec) *func([]byte, aper.DecodeState) (UplinkNASTransport, error) {
	return &v.decode
}
func BridgeUplinkNASTransportValueCodecFieldEncode(v *UplinkNASTransportValueCodec) *func(UplinkNASTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportValueCodecFieldPath(v *UplinkNASTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldPerPadding(v *UplinkNonUEAssociatedLPPaTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReceived(v *UplinkNonUEAssociatedLPPaTransport) *bool {
	return &v.received
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedAbsolute(v *UplinkNonUEAssociatedLPPaTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedBytes(v *UplinkNonUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedLocation(v *UplinkNonUEAssociatedLPPaTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v *UplinkNonUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(v *UplinkNonUEAssociatedLPPaTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(v *UplinkNonUEAssociatedLPPaTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCapture(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *func(UplinkNonUEAssociatedLPPaTransport, aper.DecodeState) (UplinkNonUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCompare(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *func(UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldContext(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldDecode(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *func([]byte, aper.DecodeState) (UplinkNonUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldEncode(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *func(UplinkNonUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldPath(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingFieldPerPadding(v *UplinkS1cdma2000tunnelling) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUplinkS1cdma2000tunnellingFieldReceived(v *UplinkS1cdma2000tunnelling) *bool {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingFieldReceivedAbsolute(v *UplinkS1cdma2000tunnelling) *bool {
	return &v.receivedAbsolute
}
func BridgeUplinkS1cdma2000tunnellingFieldReceivedBytes(v *UplinkS1cdma2000tunnelling) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUplinkS1cdma2000tunnellingFieldReceivedLocation(v *UplinkS1cdma2000tunnelling) *aper.Location {
	return &v.receivedLocation
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v *UplinkS1cdma2000tunnelling, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERFrom(v *UplinkS1cdma2000tunnelling, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERWithOptions(v *UplinkS1cdma2000tunnelling, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingValueCodec) *func(UplinkS1cdma2000tunnelling, aper.DecodeState) (UplinkS1cdma2000tunnelling, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingValueCodec) *func(UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldContext(v *UplinkS1cdma2000tunnellingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnelling, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingValueCodec) *func(UplinkS1cdma2000tunnelling, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldPath(v *UplinkS1cdma2000tunnellingValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkUEAssociatedLPPaTransportFieldPerPadding(v *UplinkUEAssociatedLPPaTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReceived(v *UplinkUEAssociatedLPPaTransport) *bool {
	return &v.received
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReceivedAbsolute(v *UplinkUEAssociatedLPPaTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReceivedBytes(v *UplinkUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReceivedLocation(v *UplinkUEAssociatedLPPaTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v *UplinkUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(v *UplinkUEAssociatedLPPaTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(v *UplinkUEAssociatedLPPaTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCapture(v *UplinkUEAssociatedLPPaTransportValueCodec) *func(UplinkUEAssociatedLPPaTransport, aper.DecodeState) (UplinkUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCompare(v *UplinkUEAssociatedLPPaTransportValueCodec) *func(UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldContext(v *UplinkUEAssociatedLPPaTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldDecode(v *UplinkUEAssociatedLPPaTransportValueCodec) *func([]byte, aper.DecodeState) (UplinkUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldEncode(v *UplinkUEAssociatedLPPaTransportValueCodec) *func(UplinkUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldPath(v *UplinkUEAssociatedLPPaTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeUserLocationInformationFieldPerPadding(v *UserLocationInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUserLocationInformationFieldReceived(v *UserLocationInformation) *bool { return &v.received }
func BridgeUserLocationInformationFieldReceivedBytes(v *UserLocationInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUserLocationInformationFieldReceivedLocation(v *UserLocationInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeUserLocationInformationMethodMarshalAPERBudget(v *UserLocationInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUserLocationInformationMethodUnmarshalAPERFrom(v *UserLocationInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func (v *ResetAcknowledgeIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 93:
		if value, ok := v.AsUEAssociatedLogicalS1ConnectionListResAck(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}
