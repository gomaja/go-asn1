// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s31 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s31

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
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	big "math/big"
)

// ConnectionEstablishmentIndicationIEContainer is ProtocolIE-Container {{ConnectionEstablishmentIndicationIEs}} of TS 36.413: a list of ConnectionEstablishmentIndicationIEField values.
type ConnectionEstablishmentIndicationIEContainer []ConnectionEstablishmentIndicationIEField

// ConnectionEstablishmentIndicationIEField is ProtocolIE-Field {{ConnectionEstablishmentIndicationIEs}} of TS 36.413: an information element field.
type ConnectionEstablishmentIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ConnectionEstablishmentIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationIEField) WithoutReplay() ConnectionEstablishmentIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ConnectionEstablishmentIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ConnectionEstablishmentIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ConnectionEstablishmentIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ConnectionEstablishmentIndicationIEField{}
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
	var zero ConnectionEstablishmentIndicationIEValue

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

// UEInformationTransferIEContainer is ProtocolIE-Container {{UEInformationTransferIEs}} of TS 36.413: a list of UEInformationTransferIEField values.
type UEInformationTransferIEContainer []UEInformationTransferIEField

// UEInformationTransferIEField is ProtocolIE-Field {{UEInformationTransferIEs}} of TS 36.413: an information element field.
type UEInformationTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEInformationTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEField) WithoutReplay() UEInformationTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEInformationTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEInformationTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEInformationTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEInformationTransferIEField{}
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
	var zero UEInformationTransferIEValue

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
func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainer(v *ConnectionEstablishmentIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainer(v *ConnectionEstablishmentIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.ServedDCNsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.ServedDCNsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.ServedGUMMEIsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.ServedGUMMEIsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SourceNgRanNodeIDExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SourceNgRanNodeIDExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SourceeNBIDExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SourceeNBIDExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SupportedTAsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SupportedTAsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SynchronisationInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SynchronisationInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TABasedMDTExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TABasedMDTExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SensorMeasurementConfigurationValueCodec is the concrete ValueCodec[SensorMeasurementConfiguration].
type SensorMeasurementConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorMeasurementConfiguration,

		error)
	encode func(SensorMeasurementConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorMeasurementConfiguration, aper.DecodeState,

	) (SensorMeasurementConfiguration, aper.Snapshot,

	)
	compare func(SensorMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorMeasurementConfigurationValueCodec) New(value SensorMeasurementConfiguration,

) (SensorMeasurementConfigurationAPERValue, error) {
	if c.encode == nil {
		return SensorMeasurementConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorMeasurementConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorMeasurementConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorMeasurementConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorMeasurementConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorMeasurementConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorMeasurementConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorMeasurementConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorMeasurementConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorMeasurementConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorMeasurementConfigurationValueCodec) EncodeAPER(value SensorMeasurementConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SensorMeasurementConfigurationValueCodec) encodeBudgetValue(value SensorMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorMeasurementConfigurationValueCodec) encodeChanged(value SensorMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SynchronisationInformationValueCodec is the concrete ValueCodec[SynchronisationInformation].
type SynchronisationInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SynchronisationInformation,

		error)
	encode func(SynchronisationInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SynchronisationInformation, aper.DecodeState,

	) (SynchronisationInformation, aper.Snapshot,

	)
	compare func(SynchronisationInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SynchronisationInformationValueCodec) New(value SynchronisationInformation,

) (SynchronisationInformationAPERValue, error) {
	if c.encode == nil {
		return SynchronisationInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SynchronisationInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SynchronisationInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SynchronisationInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SynchronisationInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SynchronisationInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SynchronisationInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SynchronisationInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SynchronisationInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SynchronisationInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SynchronisationInformationValueCodec) EncodeAPER(value SynchronisationInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SynchronisationInformationValueCodec) encodeBudgetValue(value SynchronisationInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SynchronisationInformationValueCodec) encodeChanged(value SynchronisationInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNodeIDValueCodec is the concrete ValueCodec[SourceNodeID].
type SourceNodeIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNodeID,

		error)
	encode func(SourceNodeID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNodeID, aper.DecodeState,

	) (SourceNodeID, aper.Snapshot,

	)
	compare func(SourceNodeID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNodeIDValueCodec) New(value SourceNodeID,

) (SourceNodeIDAPERValue, error) {
	if c.encode == nil {
		return SourceNodeIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNodeIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNodeIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNodeIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNodeIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNodeIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNodeIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNodeIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNodeIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNodeIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNodeIDValueCodec) EncodeAPER(value SourceNodeIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceNodeIDValueCodec) encodeBudgetValue(value SourceNodeID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNodeIDValueCodec) encodeChanged(value SourceNodeID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationMMEUES1APIDIEBinding binds MMEUES1APID to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationENBUES1APIDIEBinding binds ENBUES1APID to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationENBUES1APIDIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationUERadioCapabilityIEBinding binds UERadioCapability to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationUERadioCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityValueCodec
	inject func(s00.UERadioCapability,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.UERadioCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) Codec() s02.UERadioCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) New(value s00.UERadioCapability,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.UERadioCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding binds EnhancedCoverageRestricted to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EnhancedCoverageRestrictedValueCodec
	inject func(s00.EnhancedCoverageRestricted,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.EnhancedCoverageRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding) Codec() s00.EnhancedCoverageRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding) New(value s00.EnhancedCoverageRestricted,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.EnhancedCoverageRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding binds DLCPSecurityInformation to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s15.DLCPSecurityInformationValueCodec
	inject func(s15.DLCPSecurityInformation,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s15.DLCPSecurityInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) Codec() s15.DLCPSecurityInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) New(value s15.DLCPSecurityInformation,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s15.BridgeDLCPSecurityInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s15.DLCPSecurityInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding binds CEModeBRestricted to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBRestrictedValueCodec
	inject func(s00.CEModeBRestricted,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.CEModeBRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding) Codec() s00.CEModeBRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding) New(value s00.CEModeBRestricted,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.CEModeBRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationEndIndicationIEBinding binds EndIndication to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationEndIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EndIndicationValueCodec
	inject func(s00.EndIndication,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.EndIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationEndIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationEndIndicationIEBinding) Codec() s00.EndIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationEndIndicationIEBinding) New(value s00.EndIndication,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEndIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationEndIndicationIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.EndIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding binds SubscriptionBasedUEDifferentiationInfo to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(SubscriptionBasedUEDifferentiationInfo,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) New(value SubscriptionBasedUEDifferentiationInfo,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SubscriptionBasedUEDifferentiationInfoValueCodec is the concrete ValueCodec[SubscriptionBasedUEDifferentiationInfo].
type SubscriptionBasedUEDifferentiationInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfo,

		error)
	encode func(SubscriptionBasedUEDifferentiationInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SubscriptionBasedUEDifferentiationInfo, aper.DecodeState,

	) (SubscriptionBasedUEDifferentiationInfo, aper.Snapshot,

	)
	compare func(SubscriptionBasedUEDifferentiationInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) New(value SubscriptionBasedUEDifferentiationInfo,

) (SubscriptionBasedUEDifferentiationInfoAPERValue, error) {
	if c.encode == nil {
		return SubscriptionBasedUEDifferentiationInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SubscriptionBasedUEDifferentiationInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SubscriptionBasedUEDifferentiationInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SubscriptionBasedUEDifferentiationInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SubscriptionBasedUEDifferentiationInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SubscriptionBasedUEDifferentiationInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SubscriptionBasedUEDifferentiationInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SubscriptionBasedUEDifferentiationInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SubscriptionBasedUEDifferentiationInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) EncodeAPER(value SubscriptionBasedUEDifferentiationInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) encodeBudgetValue(value SubscriptionBasedUEDifferentiationInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) encodeChanged(value SubscriptionBasedUEDifferentiationInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding binds ERABLevelQoSParameters to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s18.ERABLevelQoSParametersValueCodec
	inject func(s18.ERABLevelQoSParameters,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s18.ERABLevelQoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) Codec() s18.ERABLevelQoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) New(value s18.ERABLevelQoSParameters,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeERABLevelQoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s18.ERABLevelQoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding binds UERadioCapabilityID to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationMaskedIMEISVIEBinding binds MaskedIMEISV to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationMaskedIMEISVIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MaskedIMEISVValueCodec
	inject func(s00.MaskedIMEISV,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.MaskedIMEISV,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) Codec() s01.MaskedIMEISVValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) New(value s00.MaskedIMEISV,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.MaskedIMEISV,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationCoarseUELocationIEBinding binds CoarseUELocation to the ConnectionEstablishmentIndicationIEs object set of TS 36.413.
type ConnectionEstablishmentIndicationCoarseUELocationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CoarseUELocationValueCodec
	inject func(s00.CoarseUELocation,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s00.CoarseUELocation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationCoarseUELocationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationCoarseUELocationIEBinding) Codec() s00.CoarseUELocationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationCoarseUELocationIEBinding) New(value s00.CoarseUELocation,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCoarseUELocationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationCoarseUELocationIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s00.CoarseUELocation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SupportedTAsValueCodec is the concrete ValueCodec[SupportedTAs].
type SupportedTAsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SupportedTAs,

		error)
	encode func(SupportedTAs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SupportedTAs, aper.DecodeState,

	) (SupportedTAs, aper.Snapshot,

	)
	compare func(SupportedTAs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SupportedTAsValueCodec) New(value SupportedTAs,

) (SupportedTAsAPERValue, error) {
	if c.encode == nil {
		return SupportedTAsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SupportedTAsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SupportedTAsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SupportedTAsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SupportedTAsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SupportedTAsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SupportedTAsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SupportedTAsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SupportedTAsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SupportedTAsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SupportedTAsValueCodec) EncodeAPER(value SupportedTAsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SupportedTAsValueCodec) encodeBudgetValue(value SupportedTAs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SupportedTAsValueCodec) encodeChanged(value SupportedTAs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectedengNBListValueCodec is the concrete ValueCodec[ConnectedengNBList].
type ConnectedengNBListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectedengNBList,

		error)
	encode func(ConnectedengNBList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectedengNBList, aper.DecodeState,

	) (ConnectedengNBList, aper.Snapshot,

	)
	compare func(ConnectedengNBList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectedengNBListValueCodec) New(value ConnectedengNBList,

) (ConnectedengNBListAPERValue, error) {
	if c.encode == nil {
		return ConnectedengNBListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectedengNBListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectedengNBListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectedengNBListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectedengNBListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectedengNBListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectedengNBListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectedengNBListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectedengNBListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectedengNBListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectedengNBListValueCodec) EncodeAPER(value ConnectedengNBListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectedengNBListValueCodec) encodeBudgetValue(value ConnectedengNBList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectedengNBListValueCodec) encodeChanged(value ConnectedengNBList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedGUMMEIsValueCodec is the concrete ValueCodec[ServedGUMMEIs].
type ServedGUMMEIsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ServedGUMMEIs,

		error)
	encode func(ServedGUMMEIs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ServedGUMMEIs, aper.DecodeState,

	) (ServedGUMMEIs, aper.Snapshot,

	)
	compare func(ServedGUMMEIs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedGUMMEIsValueCodec) New(value ServedGUMMEIs,

) (ServedGUMMEIsAPERValue, error) {
	if c.encode == nil {
		return ServedGUMMEIsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedGUMMEIsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedGUMMEIsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedGUMMEIsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedGUMMEIsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedGUMMEIsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedGUMMEIsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedGUMMEIsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedGUMMEIsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedGUMMEIsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedGUMMEIsValueCodec) EncodeAPER(value ServedGUMMEIsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ServedGUMMEIsValueCodec) encodeBudgetValue(value ServedGUMMEIs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedGUMMEIsValueCodec) encodeChanged(value ServedGUMMEIs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedDCNsValueCodec is the concrete ValueCodec[ServedDCNs].
type ServedDCNsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ServedDCNs,

		error)
	encode func(ServedDCNs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ServedDCNs, aper.DecodeState,

	) (ServedDCNs, aper.Snapshot,

	)
	compare func(ServedDCNs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedDCNsValueCodec) New(value ServedDCNs,

) (ServedDCNsAPERValue, error) {
	if c.encode == nil {
		return ServedDCNsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedDCNsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedDCNsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedDCNsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedDCNsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedDCNsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedDCNsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedDCNsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedDCNsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedDCNsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedDCNsValueCodec) EncodeAPER(value ServedDCNsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ServedDCNsValueCodec) encodeBudgetValue(value ServedDCNs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedDCNsValueCodec) encodeChanged(value ServedDCNs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferSTMSIIEBinding binds STMSI to the UEInformationTransferIEs object set of TS 36.413.
type UEInformationTransferSTMSIIEBinding struct {
	info   s00.FieldInfo
	codec  s28.STMSIValueCodec
	inject func(s28.STMSI,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s28.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferSTMSIIEBinding) Codec() s28.STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEInformationTransferSTMSIIEBinding) New(value s28.STMSI,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSTMSIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferSTMSIIEBinding) Get(field *UEInformationTransferIEField) (*s28.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferERABLevelQoSParametersIEBinding binds ERABLevelQoSParameters to the UEInformationTransferIEs object set of TS 36.413.
type UEInformationTransferERABLevelQoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s18.ERABLevelQoSParametersValueCodec
	inject func(s18.ERABLevelQoSParameters,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s18.ERABLevelQoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Codec() s18.ERABLevelQoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) New(value s18.ERABLevelQoSParameters,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeERABLevelQoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Get(field *UEInformationTransferIEField) (*s18.ERABLevelQoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferUERadioCapabilityIEBinding binds UERadioCapability to the UEInformationTransferIEs object set of TS 36.413.
type UEInformationTransferUERadioCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityValueCodec
	inject func(s00.UERadioCapability,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s00.UERadioCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferUERadioCapabilityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferUERadioCapabilityIEBinding) Codec() s02.UERadioCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferUERadioCapabilityIEBinding) New(value s00.UERadioCapability,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferUERadioCapabilityIEBinding) Get(field *UEInformationTransferIEField) (*s00.UERadioCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding binds SubscriptionBasedUEDifferentiationInfo to the UEInformationTransferIEs object set of TS 36.413.
type UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(SubscriptionBasedUEDifferentiationInfo,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) New(value SubscriptionBasedUEDifferentiationInfo,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *UEInformationTransferIEField) (*SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferPendingDataIndicationIEBinding binds PendingDataIndication to the UEInformationTransferIEs object set of TS 36.413.
type UEInformationTransferPendingDataIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PendingDataIndicationValueCodec
	inject func(s00.PendingDataIndication,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s00.PendingDataIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferPendingDataIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferPendingDataIndicationIEBinding) Codec() s01.PendingDataIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferPendingDataIndicationIEBinding) New(value s00.PendingDataIndication,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePendingDataIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferPendingDataIndicationIEBinding) Get(field *UEInformationTransferIEField) (*s00.PendingDataIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferMaskedIMEISVIEBinding binds MaskedIMEISV to the UEInformationTransferIEs object set of TS 36.413.
type UEInformationTransferMaskedIMEISVIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MaskedIMEISVValueCodec
	inject func(s00.MaskedIMEISV,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s00.MaskedIMEISV,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferMaskedIMEISVIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferMaskedIMEISVIEBinding) Codec() s01.MaskedIMEISVValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferMaskedIMEISVIEBinding) New(value s00.MaskedIMEISV,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferMaskedIMEISVIEBinding) Get(field *UEInformationTransferIEField) (*s00.MaskedIMEISV,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectedengNBItemValueCodec is the concrete ValueCodec[ConnectedengNBItem].
type ConnectedengNBItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectedengNBItem,

		error)
	encode func(ConnectedengNBItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectedengNBItem, aper.DecodeState,

	) (ConnectedengNBItem, aper.Snapshot,

	)
	compare func(ConnectedengNBItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectedengNBItemValueCodec) New(value ConnectedengNBItem,

) (ConnectedengNBItemAPERValue, error) {
	if c.encode == nil {
		return ConnectedengNBItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectedengNBItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectedengNBItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectedengNBItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectedengNBItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectedengNBItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectedengNBItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectedengNBItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectedengNBItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectedengNBItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectedengNBItemValueCodec) EncodeAPER(value ConnectedengNBItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectedengNBItemValueCodec) encodeBudgetValue(value ConnectedengNBItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectedengNBItemValueCodec) encodeChanged(value ConnectedengNBItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationValueCodec is the concrete ValueCodec[ConnectionEstablishmentIndication].
type ConnectionEstablishmentIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndication,

		error)
	encode func(ConnectionEstablishmentIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndication, aper.DecodeState,

	) (ConnectionEstablishmentIndication, aper.Snapshot,

	)
	compare func(ConnectionEstablishmentIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationValueCodec) New(value ConnectionEstablishmentIndication,

) (ConnectionEstablishmentIndicationAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationValueCodec) encodeChanged(value ConnectionEstablishmentIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorMeasConfigNameItemValueCodec is the concrete ValueCodec[SensorMeasConfigNameItem].
type SensorMeasConfigNameItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorMeasConfigNameItem,

		error)
	encode func(SensorMeasConfigNameItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorMeasConfigNameItem, aper.DecodeState,

	) (SensorMeasConfigNameItem, aper.Snapshot,

	)
	compare func(SensorMeasConfigNameItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorMeasConfigNameItemValueCodec) New(value SensorMeasConfigNameItem,

) (SensorMeasConfigNameItemAPERValue, error) {
	if c.encode == nil {
		return SensorMeasConfigNameItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorMeasConfigNameItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorMeasConfigNameItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorMeasConfigNameItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorMeasConfigNameItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorMeasConfigNameItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorMeasConfigNameItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorMeasConfigNameItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorMeasConfigNameItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorMeasConfigNameItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorMeasConfigNameItemValueCodec) EncodeAPER(value SensorMeasConfigNameItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SensorMeasConfigNameItemValueCodec) encodeBudgetValue(value SensorMeasConfigNameItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorMeasConfigNameItemValueCodec) encodeChanged(value SensorMeasConfigNameItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorMeasConfigNameListValueCodec is the concrete ValueCodec[SensorMeasConfigNameList].
type SensorMeasConfigNameListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorMeasConfigNameList,

		error)
	encode func(SensorMeasConfigNameList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorMeasConfigNameList, aper.DecodeState,

	) (SensorMeasConfigNameList, aper.Snapshot,

	)
	compare func(SensorMeasConfigNameList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorMeasConfigNameListValueCodec) New(value SensorMeasConfigNameList,

) (SensorMeasConfigNameListAPERValue, error) {
	if c.encode == nil {
		return SensorMeasConfigNameListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorMeasConfigNameListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorMeasConfigNameListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorMeasConfigNameListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorMeasConfigNameListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorMeasConfigNameListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorMeasConfigNameListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorMeasConfigNameListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorMeasConfigNameListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorMeasConfigNameListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorMeasConfigNameListValueCodec) EncodeAPER(value SensorMeasConfigNameListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SensorMeasConfigNameListValueCodec) encodeBudgetValue(value SensorMeasConfigNameList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorMeasConfigNameListValueCodec) encodeChanged(value SensorMeasConfigNameList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorNameConfigValueCodec is the concrete ValueCodec[SensorNameConfig].
type SensorNameConfigValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s30.SensorNameConfig,

		error)
	encode func(s30.SensorNameConfig,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s30.SensorNameConfig, aper.DecodeState,

	) (s30.SensorNameConfig, aper.Snapshot,

	)
	compare func(s30.SensorNameConfig, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorNameConfigValueCodec) New(value s30.SensorNameConfig,

) (SensorNameConfigAPERValue, error) {
	if c.encode == nil {
		return SensorNameConfigAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorNameConfigAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorNameConfigAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorNameConfigAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorNameConfigValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorNameConfigAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorNameConfigAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorNameConfigAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorNameConfigAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorNameConfigAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorNameConfigValueCodec) EncodeAPER(value SensorNameConfigAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SensorNameConfigValueCodec) encodeBudgetValue(value s30.SensorNameConfig,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorNameConfigValueCodec) encodeChanged(value s30.SensorNameConfig,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedDCNsItemValueCodec is the concrete ValueCodec[ServedDCNsItem].
type ServedDCNsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ServedDCNsItem,

		error)
	encode func(ServedDCNsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ServedDCNsItem, aper.DecodeState,

	) (ServedDCNsItem, aper.Snapshot,

	)
	compare func(ServedDCNsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedDCNsItemValueCodec) New(value ServedDCNsItem,

) (ServedDCNsItemAPERValue, error) {
	if c.encode == nil {
		return ServedDCNsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedDCNsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedDCNsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedDCNsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedDCNsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedDCNsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedDCNsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedDCNsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedDCNsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedDCNsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedDCNsItemValueCodec) EncodeAPER(value ServedDCNsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ServedDCNsItemValueCodec) encodeBudgetValue(value ServedDCNsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedDCNsItemValueCodec) encodeChanged(value ServedDCNsItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedGUMMEIsItemValueCodec is the concrete ValueCodec[ServedGUMMEIsItem].
type ServedGUMMEIsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ServedGUMMEIsItem,

		error)
	encode func(ServedGUMMEIsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ServedGUMMEIsItem, aper.DecodeState,

	) (ServedGUMMEIsItem, aper.Snapshot,

	)
	compare func(ServedGUMMEIsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedGUMMEIsItemValueCodec) New(value ServedGUMMEIsItem,

) (ServedGUMMEIsItemAPERValue, error) {
	if c.encode == nil {
		return ServedGUMMEIsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedGUMMEIsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedGUMMEIsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedGUMMEIsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedGUMMEIsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedGUMMEIsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedGUMMEIsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedGUMMEIsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedGUMMEIsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedGUMMEIsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedGUMMEIsItemValueCodec) EncodeAPER(value ServedGUMMEIsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ServedGUMMEIsItemValueCodec) encodeBudgetValue(value ServedGUMMEIsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedGUMMEIsItemValueCodec) encodeChanged(value ServedGUMMEIsItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNgRanNodeIDValueCodec is the concrete ValueCodec[SourceNgRanNodeID].
type SourceNgRanNodeIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNgRanNodeID,

		error)
	encode func(SourceNgRanNodeID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNgRanNodeID, aper.DecodeState,

	) (SourceNgRanNodeID, aper.Snapshot,

	)
	compare func(SourceNgRanNodeID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNgRanNodeIDValueCodec) New(value SourceNgRanNodeID,

) (SourceNgRanNodeIDAPERValue, error) {
	if c.encode == nil {
		return SourceNgRanNodeIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNgRanNodeIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNgRanNodeIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNgRanNodeIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNgRanNodeIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNgRanNodeIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNgRanNodeIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNgRanNodeIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNgRanNodeIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNgRanNodeIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNgRanNodeIDValueCodec) EncodeAPER(value SourceNgRanNodeIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceNgRanNodeIDValueCodec) encodeBudgetValue(value SourceNgRanNodeID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNgRanNodeIDValueCodec) encodeChanged(value SourceNgRanNodeID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SupportedTAsItemValueCodec is the concrete ValueCodec[SupportedTAsItem].
type SupportedTAsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SupportedTAsItem,

		error)
	encode func(SupportedTAsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SupportedTAsItem, aper.DecodeState,

	) (SupportedTAsItem, aper.Snapshot,

	)
	compare func(SupportedTAsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SupportedTAsItemValueCodec) New(value SupportedTAsItem,

) (SupportedTAsItemAPERValue, error) {
	if c.encode == nil {
		return SupportedTAsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SupportedTAsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SupportedTAsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SupportedTAsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SupportedTAsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SupportedTAsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SupportedTAsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SupportedTAsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SupportedTAsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SupportedTAsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SupportedTAsItemValueCodec) EncodeAPER(value SupportedTAsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SupportedTAsItemValueCodec) encodeBudgetValue(value SupportedTAsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SupportedTAsItemValueCodec) encodeChanged(value SupportedTAsItem,

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
func BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(fields ConnectionEstablishmentIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeServedDCNsItemExtIEsValueValidateS1APExtensionContainer(fields s11.ServedDCNsItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.ServedDCNsItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.ServedDCNsItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeServedDCNsItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeServedGUMMEIsItemExtIEsValueValidateS1APExtensionContainer(fields s11.ServedGUMMEIsItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.ServedGUMMEIsItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.ServedGUMMEIsItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeServedGUMMEIsItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSourceNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields s11.SourceNgRanNodeIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SourceNgRanNodeIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SourceNgRanNodeIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSourceNgRanNodeIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSourceeNBIDExtIEsValueValidateS1APExtensionContainer(fields s11.SourceeNBIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SourceeNBIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SourceeNBIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSourceeNBIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APExtensionContainer(fields s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SubscriptionBasedUEDifferentiationInfoExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SubscriptionBasedUEDifferentiationInfoExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSupportedTAsItemExtIEsValueValidateS1APExtensionContainer(fields s11.SupportedTAsItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SupportedTAsItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SupportedTAsItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSupportedTAsItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSynchronisationInformationExtIEsValueValidateS1APExtensionContainer(fields s11.SynchronisationInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SynchronisationInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SynchronisationInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSynchronisationInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ConnectionEstablishmentIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ConnectionEstablishmentIndicationIEs}} codec of TS 36.413.
func ConnectionEstablishmentIndicationIEValueERABIEContainerListCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable) ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec {
	codec := ConnectionEstablishmentIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ConnectionEstablishmentIndicationIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ConnectionEstablishmentIndicationIEField
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
			return nil, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ConnectionEstablishmentIndicationIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ConnectionEstablishmentIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ConnectionEstablishmentIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ConnectionEstablishmentIndicationIEValueERABIEContainerList, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ConnectionEstablishmentIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
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

// SensorNameConfigExtIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{SensorNameConfig-ExtIEs}} codec of TS 36.413.
func SensorNameConfigExtIEValueERABIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable) s11.SensorNameConfigExtIEValueERABIEContainerListValueCodec {
	codec := s30.SensorNameConfigExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SensorNameConfigExtIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s11.SensorNameConfigExtIEValueERABIEContainerListValueCodec {
		sealed := s11.SensorNameConfigExtIEValueERABIEContainerListValueCodec{}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorNameConfigExtIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SensorNameConfigExtIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SensorNameConfigExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SensorNameConfigExtIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorNameConfigExtIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SensorNameConfigExtIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SensorNameConfigExtIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s11.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SensorNameConfigExtIEValueERABIEContainerList, options aper.DecodeState) (s11.SensorNameConfigExtIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeSensorNameConfigExtIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SensorNameConfigExtIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceNodeIDExtensionIEIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{SourceNodeID-ExtensionIE}} codec of TS 36.413.
func SourceNodeIDExtensionIEIEValueERABIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable) s11.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s11.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec {
		sealed := s11.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec{}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SourceNodeIDExtensionIEIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SourceNodeIDExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNodeIDExtensionIEIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&codec))(s11.SourceNodeIDExtensionIEIEContainer(value), fresh, budget)
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedDCNsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ServedDCNsItem-ExtIEs}} codec of TS 36.413.
func ServedDCNsItemExtIEsValueExtensionFieldTableCodec(table s00.ServedDCNsItemExtIEsValueExtensionTable) s11.ServedDCNsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeServedDCNsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.ServedDCNsItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.ServedDCNsItemExtIEsExtFieldValueCodec {
		sealed := s11.ServedDCNsItemExtIEsExtFieldValueCodec{}
		*s11.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ServedDCNsItemExtIEsExtField, error) {
			var field s11.ServedDCNsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ServedDCNsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ServedDCNsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ServedDCNsItemExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.ServedDCNsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeServedDCNsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.ServedDCNsItemExtIEsExtField, options aper.DecodeState) (s11.ServedDCNsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.ServedDCNsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedGUMMEIsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ServedGUMMEIsItem-ExtIEs}} codec of TS 36.413.
func ServedGUMMEIsItemExtIEsValueExtensionFieldTableCodec(table s00.ServedGUMMEIsItemExtIEsValueExtensionTable) s11.ServedGUMMEIsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeServedGUMMEIsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.ServedGUMMEIsItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.ServedGUMMEIsItemExtIEsExtFieldValueCodec {
		sealed := s11.ServedGUMMEIsItemExtIEsExtFieldValueCodec{}
		*s11.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ServedGUMMEIsItemExtIEsExtField, error) {
			var field s11.ServedGUMMEIsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ServedGUMMEIsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ServedGUMMEIsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ServedGUMMEIsItemExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.ServedGUMMEIsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeServedGUMMEIsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.ServedGUMMEIsItemExtIEsExtField, options aper.DecodeState) (s11.ServedGUMMEIsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.ServedGUMMEIsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceNgRanNodeIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SourceNgRanNode-ID-ExtIEs}} codec of TS 36.413.
func SourceNgRanNodeIDExtIEsValueExtensionFieldTableCodec(table s00.SourceNgRanNodeIDExtIEsValueExtensionTable) s11.SourceNgRanNodeIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeSourceNgRanNodeIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SourceNgRanNodeIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.SourceNgRanNodeIDExtIEsExtFieldValueCodec {
		sealed := s11.SourceNgRanNodeIDExtIEsExtFieldValueCodec{}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNgRanNodeIDExtIEsExtField, error) {
			var field s11.SourceNgRanNodeIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceNgRanNodeIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNgRanNodeIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceNgRanNodeIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SourceNgRanNodeIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SourceNgRanNodeIDExtIEsExtField, options aper.DecodeState) (s11.SourceNgRanNodeIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SourceNgRanNodeIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceeNBIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SourceeNB-ID-ExtIEs}} codec of TS 36.413.
func SourceeNBIDExtIEsValueExtensionFieldTableCodec(table s00.SourceeNBIDExtIEsValueExtensionTable) s11.SourceeNBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeSourceeNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SourceeNBIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.SourceeNBIDExtIEsExtFieldValueCodec {
		sealed := s11.SourceeNBIDExtIEsExtFieldValueCodec{}
		*s11.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceeNBIDExtIEsExtField, error) {
			var field s11.SourceeNBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSourceeNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceeNBIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceeNBIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceeNBIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SourceeNBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSourceeNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SourceeNBIDExtIEsExtField, options aper.DecodeState) (s11.SourceeNBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SourceeNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Subscription-Based-UE-DifferentiationInfo-ExtIEs}} codec of TS 36.413.
func SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionFieldTableCodec(table s00.SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTable) s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec{}
	}
	return func() s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec {
		sealed := s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec{}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, error) {
			var field s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SubscriptionBasedUEDifferentiationInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfoExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, options aper.DecodeState) (s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SupportedTAsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SupportedTAs-Item-ExtIEs}} codec of TS 36.413.
func SupportedTAsItemExtIEsValueExtensionFieldTableCodec(table s00.SupportedTAsItemExtIEsValueExtensionTable) s11.SupportedTAsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeSupportedTAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SupportedTAsItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.SupportedTAsItemExtIEsExtFieldValueCodec {
		sealed := s11.SupportedTAsItemExtIEsExtFieldValueCodec{}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SupportedTAsItemExtIEsExtField, error) {
			var field s11.SupportedTAsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SupportedTAsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SupportedTAsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SupportedTAsItemExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SupportedTAsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SupportedTAsItemExtIEsExtField, options aper.DecodeState) (s11.SupportedTAsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SupportedTAsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SynchronisationInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SynchronisationInformation-ExtIEs}} codec of TS 36.413.
func SynchronisationInformationExtIEsValueExtensionFieldTableCodec(table s00.SynchronisationInformationExtIEsValueExtensionTable) s11.SynchronisationInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeSynchronisationInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SynchronisationInformationExtIEsExtFieldValueCodec{}
	}
	return func() s11.SynchronisationInformationExtIEsExtFieldValueCodec {
		sealed := s11.SynchronisationInformationExtIEsExtFieldValueCodec{}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SynchronisationInformationExtIEsExtField, error) {
			var field s11.SynchronisationInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SynchronisationInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SynchronisationInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SynchronisationInformationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SynchronisationInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SynchronisationInformationExtIEsExtField, options aper.DecodeState) (s11.SynchronisationInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SynchronisationInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TABasedMDTExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TABasedMDT-ExtIEs}} codec of TS 36.413.
func TABasedMDTExtIEsValueExtensionFieldTableCodec(table s00.TABasedMDTExtIEsValueExtensionTable) s11.TABasedMDTExtIEsExtFieldValueCodec {
	if !*s00.BridgeTABasedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TABasedMDTExtIEsExtFieldValueCodec{}
	}
	return func() s11.TABasedMDTExtIEsExtFieldValueCodec {
		sealed := s11.TABasedMDTExtIEsExtFieldValueCodec{}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TABasedMDTExtIEsExtField, error) {
			var field s11.TABasedMDTExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTABasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TABasedMDTExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TABasedMDTExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TABasedMDTExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TABasedMDTExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTABasedMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TABasedMDTExtIEsExtField, options aper.DecodeState) (s11.TABasedMDTExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TABasedMDTExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedDCNsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ServedDCNsItem-ExtIEs}} codec of TS 36.413.
func ServedDCNsItemExtIEsValueExtensionTableCodec(table s00.ServedDCNsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.ServedDCNsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeServedDCNsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.ServedDCNsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.ServedDCNsItemExtIEsExtContainerValueCodec {
		sealed := s11.ServedDCNsItemExtIEsExtContainerValueCodec{}
		*s11.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ServedDCNsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.ServedDCNsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.ServedDCNsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ServedDCNsItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ServedDCNsItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ServedDCNsItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.ServedDCNsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeServedDCNsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.ServedDCNsItemExtIEsExtContainer, options aper.DecodeState) (s11.ServedDCNsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.ServedDCNsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ServedGUMMEIsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ServedGUMMEIsItem-ExtIEs}} codec of TS 36.413.
func ServedGUMMEIsItemExtIEsValueExtensionTableCodec(table s00.ServedGUMMEIsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.ServedGUMMEIsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeServedGUMMEIsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.ServedGUMMEIsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.ServedGUMMEIsItemExtIEsExtContainerValueCodec {
		sealed := s11.ServedGUMMEIsItemExtIEsExtContainerValueCodec{}
		*s11.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ServedGUMMEIsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.ServedGUMMEIsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.ServedGUMMEIsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ServedGUMMEIsItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ServedGUMMEIsItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ServedGUMMEIsItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.ServedGUMMEIsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeServedGUMMEIsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.ServedGUMMEIsItemExtIEsExtContainer, options aper.DecodeState) (s11.ServedGUMMEIsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.ServedGUMMEIsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SourceNgRanNodeIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SourceNgRanNode-ID-ExtIEs}} codec of TS 36.413.
func SourceNgRanNodeIDExtIEsValueExtensionTableCodec(table s00.SourceNgRanNodeIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SourceNgRanNodeIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeSourceNgRanNodeIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SourceNgRanNodeIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SourceNgRanNodeIDExtIEsExtContainerValueCodec {
		sealed := s11.SourceNgRanNodeIDExtIEsExtContainerValueCodec{}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNgRanNodeIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SourceNgRanNodeIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SourceNgRanNodeIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SourceNgRanNodeIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNgRanNodeIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SourceNgRanNodeIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SourceNgRanNodeIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SourceNgRanNodeIDExtIEsExtContainer, options aper.DecodeState) (s11.SourceNgRanNodeIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SourceNgRanNodeIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SourceeNBIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SourceeNB-ID-ExtIEs}} codec of TS 36.413.
func SourceeNBIDExtIEsValueExtensionTableCodec(table s00.SourceeNBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SourceeNBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeSourceeNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SourceeNBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SourceeNBIDExtIEsExtContainerValueCodec {
		sealed := s11.SourceeNBIDExtIEsExtContainerValueCodec{}
		*s11.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceeNBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SourceeNBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SourceeNBIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSourceeNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SourceeNBIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceeNBIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SourceeNBIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SourceeNBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSourceeNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SourceeNBIDExtIEsExtContainer, options aper.DecodeState) (s11.SourceeNBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SourceeNBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Subscription-Based-UE-DifferentiationInfo-ExtIEs}} codec of TS 36.413.
func SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableCodec(table s00.SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec {
		sealed := s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec{}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, options aper.DecodeState) (s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SupportedTAsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SupportedTAs-Item-ExtIEs}} codec of TS 36.413.
func SupportedTAsItemExtIEsValueExtensionTableCodec(table s00.SupportedTAsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SupportedTAsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeSupportedTAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SupportedTAsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SupportedTAsItemExtIEsExtContainerValueCodec {
		sealed := s11.SupportedTAsItemExtIEsExtContainerValueCodec{}
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SupportedTAsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SupportedTAsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SupportedTAsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SupportedTAsItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SupportedTAsItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SupportedTAsItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SupportedTAsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SupportedTAsItemExtIEsExtContainer, options aper.DecodeState) (s11.SupportedTAsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SupportedTAsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SynchronisationInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SynchronisationInformation-ExtIEs}} codec of TS 36.413.
func SynchronisationInformationExtIEsValueExtensionTableCodec(table s00.SynchronisationInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SynchronisationInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeSynchronisationInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SynchronisationInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SynchronisationInformationExtIEsExtContainerValueCodec {
		sealed := s11.SynchronisationInformationExtIEsExtContainerValueCodec{}
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SynchronisationInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SynchronisationInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SynchronisationInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SynchronisationInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SynchronisationInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SynchronisationInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SynchronisationInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SynchronisationInformationExtIEsExtContainer, options aper.DecodeState) (s11.SynchronisationInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SynchronisationInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ConnectionEstablishmentIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ConnectionEstablishmentIndicationIEs}} codec of TS 36.413.
func ConnectionEstablishmentIndicationIEValueIEFieldTableCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable) ConnectionEstablishmentIndicationIEFieldValueCodec {
	if !*s00.BridgeConnectionEstablishmentIndicationIEValueIETableFieldBound(&table) {
		return ConnectionEstablishmentIndicationIEFieldValueCodec{}
	}
	return ConnectionEstablishmentIndicationIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ConnectionEstablishmentIndicationIEField, error) {
		var field ConnectionEstablishmentIndicationIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ConnectionEstablishmentIndicationIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEField")
		}
		return field, nil
	}, encode: func(field ConnectionEstablishmentIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ConnectionEstablishmentIndicationIEField, options aper.DecodeState) (ConnectionEstablishmentIndicationIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ConnectionEstablishmentIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEField(&v, &s)
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

// SourceNodeIDExtensionIEIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{SourceNodeID-ExtensionIE}} codec of TS 36.413.
func SourceNodeIDExtensionIEIEValueIEFieldTableCodec(table s00.SourceNodeIDExtensionIEIEValueIETable) s11.SourceNodeIDExtensionIEIEFieldValueCodec {
	if !*s00.BridgeSourceNodeIDExtensionIEIEValueIETableFieldBound(&table) {
		return s11.SourceNodeIDExtensionIEIEFieldValueCodec{}
	}
	return func() s11.SourceNodeIDExtensionIEIEFieldValueCodec {
		sealed := s11.SourceNodeIDExtensionIEIEFieldValueCodec{}
		*s11.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEField, error) {
			var field s11.SourceNodeIDExtensionIEIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNodeIDExtensionIEIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEField")
			}
			return field, nil
		}
		*s11.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldEncode(&sealed) = func(field s11.SourceNodeIDExtensionIEIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSourceNodeIDExtensionIEIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldCapture(&sealed) = func(v s11.SourceNodeIDExtensionIEIEField, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldCompare(&sealed) = func(v s11.SourceNodeIDExtensionIEIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ConnectionEstablishmentIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{ConnectionEstablishmentIndicationIEs}} codec of TS 36.413.
func ConnectionEstablishmentIndicationIEValueIETableCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable, bounds aper.ListBounds) ConnectionEstablishmentIndicationIEContainerValueCodec {
	if !*s00.BridgeConnectionEstablishmentIndicationIEValueIETableFieldBound(&table) {
		return ConnectionEstablishmentIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ConnectionEstablishmentIndicationIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ConnectionEstablishmentIndicationIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ConnectionEstablishmentIndicationIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ConnectionEstablishmentIndicationIEField
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
			return nil, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ConnectionEstablishmentIndicationIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEContainer")
		}
		return fields, nil
	},
		encode: func(fields ConnectionEstablishmentIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ConnectionEstablishmentIndicationIEContainer, options aper.DecodeState) (ConnectionEstablishmentIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ConnectionEstablishmentIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// SourceNodeIDExtensionIEIEValueIETableCodec constructs the ProtocolIE-Container {{SourceNodeID-ExtensionIE}} codec of TS 36.413.
func SourceNodeIDExtensionIEIEValueIETableCodec(table s00.SourceNodeIDExtensionIEIEValueIETable, bounds aper.ListBounds) s11.SourceNodeIDExtensionIEIEContainerValueCodec {
	if !*s00.BridgeSourceNodeIDExtensionIEIEValueIETableFieldBound(&table) {
		return s11.SourceNodeIDExtensionIEIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SourceNodeIDExtensionIEIEContainerValueCodec {
		sealed := s11.SourceNodeIDExtensionIEIEContainerValueCodec{}
		*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SourceNodeIDExtensionIEIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SourceNodeIDExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNodeIDExtensionIEIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEContainer")
			}
			return fields, nil
		}
		*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&sealed) = func(fields s11.SourceNodeIDExtensionIEIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSourceNodeIDExtensionIEIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldCapture(&sealed) = func(v s11.SourceNodeIDExtensionIEIEContainer, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldCompare(&sealed) = func(v s11.SourceNodeIDExtensionIEIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ConnectionEstablishmentIndicationIEs}} codec of TS 36.413.
func ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable) ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := ConnectionEstablishmentIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ConnectionEstablishmentIndicationIEField
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
			return nil, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ConnectionEstablishmentIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolErrorIEContainerList(
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

// SensorNameConfigExtIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{SensorNameConfig-ExtIEs}} codec of TS 36.413.
func SensorNameConfigExtIEValueProtocolErrorIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable) s11.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec {
	codec := s30.SensorNameConfigExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s11.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s11.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec{}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SensorNameConfigExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SensorNameConfigExtIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorNameConfigExtIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SensorNameConfigExtIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s11.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeSensorNameConfigExtIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{SourceNodeID-ExtensionIE}} codec of TS 36.413.
func SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable) s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SourceNodeIDExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&codec))(s11.SourceNodeIDExtensionIEIEContainer(value), fresh, budget)
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ConnectionEstablishmentIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ConnectionEstablishmentIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ConnectionEstablishmentIndicationIEValueProtocolIEContainerListCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable, bounds aper.ListBounds) ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec {
	codec := ConnectionEstablishmentIndicationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ConnectionEstablishmentIndicationIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ConnectionEstablishmentIndicationIEField
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
			return nil, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ConnectionEstablishmentIndicationIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ConnectionEstablishmentIndicationIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ConnectionEstablishmentIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// SensorNameConfigExtIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {SensorNameConfig-ExtIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func SensorNameConfigExtIEValueProtocolIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable, bounds aper.ListBounds) s11.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec {
	codec := s30.SensorNameConfigExtIEValueIETableCodec(table, bounds)
	if *s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s11.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec {
		sealed := s11.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec{}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorNameConfigExtIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SensorNameConfigExtIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SensorNameConfigExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SensorNameConfigExtIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorNameConfigExtIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SensorNameConfigExtIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SensorNameConfigExtIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s11.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SensorNameConfigExtIEValueProtocolIEContainerList, options aper.DecodeState) (s11.SensorNameConfigExtIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SensorNameConfigExtIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SourceNodeIDExtensionIEIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {SourceNodeID-ExtensionIE} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func SourceNodeIDExtensionIEIEValueProtocolIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable, bounds aper.ListBounds) s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, bounds)
	if *s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec {
		sealed := s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec{}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SourceNodeIDExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNodeIDExtensionIEIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&codec))(s11.SourceNodeIDExtensionIEIEContainer(value), fresh, budget)
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// connectionEstablishmentIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ConnectionEstablishmentIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ConnectionEstablishmentIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEField(v *ConnectionEstablishmentIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEField(v *ConnectionEstablishmentIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// sensorNameConfigExtIEValueProtocolOpenValue is the concrete protocolOpenValue[SensorNameConfigExtIEValue].
type SensorNameConfigExtIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SensorNameConfigExtIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SensorNameConfigExtIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// servedDCNsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ServedDCNsItemExtIEsValue].
type ServedDCNsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.ServedDCNsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.ServedDCNsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.ServedDCNsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeServedDCNsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeServedDCNsItemExtIEsExtFieldFieldReplay(v), *s11.BridgeServedDCNsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.ServedDCNsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeServedDCNsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeServedDCNsItemExtIEsExtFieldFieldReplay(v), *s11.BridgeServedDCNsItemExtIEsExtFieldFieldWithoutReplay(v))
}

// servedGUMMEIsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ServedGUMMEIsItemExtIEsValue].
type ServedGUMMEIsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.ServedGUMMEIsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.ServedGUMMEIsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.ServedGUMMEIsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeServedGUMMEIsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeServedGUMMEIsItemExtIEsExtFieldFieldReplay(v), *s11.BridgeServedGUMMEIsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.ServedGUMMEIsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeServedGUMMEIsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeServedGUMMEIsItemExtIEsExtFieldFieldReplay(v), *s11.BridgeServedGUMMEIsItemExtIEsExtFieldFieldWithoutReplay(v))
}

// sourceNgRanNodeIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SourceNgRanNodeIDExtIEsValue].
type SourceNgRanNodeIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SourceNgRanNodeIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SourceNgRanNodeIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SourceNgRanNodeIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSourceNgRanNodeIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSourceNgRanNodeIDExtIEsExtFieldFieldReplay(v), *s11.BridgeSourceNgRanNodeIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.SourceNgRanNodeIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSourceNgRanNodeIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSourceNgRanNodeIDExtIEsExtFieldFieldReplay(v), *s11.BridgeSourceNgRanNodeIDExtIEsExtFieldFieldWithoutReplay(v))
}

// sourceeNBIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SourceeNBIDExtIEsValue].
type SourceeNBIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SourceeNBIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SourceeNBIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SourceeNBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSourceeNBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSourceeNBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeSourceeNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.SourceeNBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSourceeNBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSourceeNBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeSourceeNBIDExtIEsExtFieldFieldWithoutReplay(v))
}

// subscriptionBasedUEDifferentiationInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SubscriptionBasedUEDifferentiationInfoExtIEsValue].
type SubscriptionBasedUEDifferentiationInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SubscriptionBasedUEDifferentiationInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SubscriptionBasedUEDifferentiationInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldReplay(v), *s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionField(v *s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldReplay(v), *s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldWithoutReplay(v))
}

// supportedTAsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SupportedTAsItemExtIEsValue].
type SupportedTAsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SupportedTAsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SupportedTAsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SupportedTAsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSupportedTAsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSupportedTAsItemExtIEsExtFieldFieldReplay(v), *s11.BridgeSupportedTAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.SupportedTAsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSupportedTAsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSupportedTAsItemExtIEsExtFieldFieldReplay(v), *s11.BridgeSupportedTAsItemExtIEsExtFieldFieldWithoutReplay(v))
}

// synchronisationInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SynchronisationInformationExtIEsValue].
type SynchronisationInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SynchronisationInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SynchronisationInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SynchronisationInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSynchronisationInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSynchronisationInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeSynchronisationInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionField(v *s11.SynchronisationInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSynchronisationInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSynchronisationInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeSynchronisationInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TABasedMDTExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTABasedMDTExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTABasedMDTExtIEsExtFieldFieldReplay(v), *s11.BridgeTABasedMDTExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionField(v *s11.TABasedMDTExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTABasedMDTExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTABasedMDTExtIEsExtFieldFieldReplay(v), *s11.BridgeTABasedMDTExtIEsExtFieldFieldWithoutReplay(v))
}

// SensorMeasurementConfigurationAPERValue is the concrete APERValue[SensorMeasurementConfiguration].
type SensorMeasurementConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   SensorMeasurementConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorMeasurementConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasurementConfigurationAPERValue) WithoutReplay() SensorMeasurementConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SynchronisationInformationAPERValue is the concrete APERValue[SynchronisationInformation].
type SynchronisationInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   SynchronisationInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SynchronisationInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SynchronisationInformationAPERValue) WithoutReplay() SynchronisationInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDAPERValue is the concrete APERValue[SourceNodeID].
type SourceNodeIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   SourceNodeID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNodeIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDAPERValue) WithoutReplay() SourceNodeIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SubscriptionBasedUEDifferentiationInfoAPERValue is the concrete APERValue[SubscriptionBasedUEDifferentiationInfo].
type SubscriptionBasedUEDifferentiationInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   SubscriptionBasedUEDifferentiationInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SubscriptionBasedUEDifferentiationInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SubscriptionBasedUEDifferentiationInfoAPERValue) WithoutReplay() SubscriptionBasedUEDifferentiationInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SupportedTAsAPERValue is the concrete APERValue[SupportedTAs].
type SupportedTAsAPERValue struct {
	context s00.BridgeCodecContext
	Value   SupportedTAs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SupportedTAsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SupportedTAsAPERValue) WithoutReplay() SupportedTAsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectedengNBListAPERValue is the concrete APERValue[ConnectedengNBList].
type ConnectedengNBListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ConnectedengNBList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectedengNBListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectedengNBListAPERValue) WithoutReplay() ConnectedengNBListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedGUMMEIsAPERValue is the concrete APERValue[ServedGUMMEIs].
type ServedGUMMEIsAPERValue struct {
	context s00.BridgeCodecContext
	Value   ServedGUMMEIs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedGUMMEIsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedGUMMEIsAPERValue) WithoutReplay() ServedGUMMEIsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedDCNsAPERValue is the concrete APERValue[ServedDCNs].
type ServedDCNsAPERValue struct {
	context s00.BridgeCodecContext
	Value   ServedDCNs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedDCNsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedDCNsAPERValue) WithoutReplay() ServedDCNsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectedengNBItemAPERValue is the concrete APERValue[ConnectedengNBItem].
type ConnectedengNBItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ConnectedengNBItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectedengNBItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectedengNBItemAPERValue) WithoutReplay() ConnectedengNBItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationAPERValue is the concrete APERValue[ConnectionEstablishmentIndication].
type ConnectionEstablishmentIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ConnectionEstablishmentIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationAPERValue) WithoutReplay() ConnectionEstablishmentIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorMeasConfigNameItemAPERValue is the concrete APERValue[SensorMeasConfigNameItem].
type SensorMeasConfigNameItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   SensorMeasConfigNameItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorMeasConfigNameItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasConfigNameItemAPERValue) WithoutReplay() SensorMeasConfigNameItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorMeasConfigNameListAPERValue is the concrete APERValue[SensorMeasConfigNameList].
type SensorMeasConfigNameListAPERValue struct {
	context s00.BridgeCodecContext
	Value   SensorMeasConfigNameList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorMeasConfigNameListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasConfigNameListAPERValue) WithoutReplay() SensorMeasConfigNameListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorNameConfigAPERValue is the concrete APERValue[SensorNameConfig].
type SensorNameConfigAPERValue struct {
	context s00.BridgeCodecContext
	Value   s30.SensorNameConfig

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorNameConfigAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorNameConfigAPERValue) WithoutReplay() SensorNameConfigAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedDCNsItemAPERValue is the concrete APERValue[ServedDCNsItem].
type ServedDCNsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ServedDCNsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedDCNsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedDCNsItemAPERValue) WithoutReplay() ServedDCNsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedGUMMEIsItemAPERValue is the concrete APERValue[ServedGUMMEIsItem].
type ServedGUMMEIsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ServedGUMMEIsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedGUMMEIsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedGUMMEIsItemAPERValue) WithoutReplay() ServedGUMMEIsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNgRanNodeIDAPERValue is the concrete APERValue[SourceNgRanNodeID].
type SourceNgRanNodeIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   SourceNgRanNodeID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNgRanNodeIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNgRanNodeIDAPERValue) WithoutReplay() SourceNgRanNodeIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SupportedTAsItemAPERValue is the concrete APERValue[SupportedTAsItem].
type SupportedTAsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   SupportedTAsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SupportedTAsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SupportedTAsItemAPERValue) WithoutReplay() SupportedTAsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeServedDCNsItemExtIEsValueValidateS1APIEContainer(fields s11.ServedDCNsItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeServedDCNsItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeServedDCNsItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeServedDCNsItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeServedGUMMEIsItemExtIEsValueValidateS1APIEContainer(fields s11.ServedGUMMEIsItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeServedGUMMEIsItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeServedGUMMEIsItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeServedGUMMEIsItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSourceNgRanNodeIDExtIEsValueValidateS1APIEContainer(fields s11.SourceNgRanNodeIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSourceNgRanNodeIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSourceNgRanNodeIDExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSourceNgRanNodeIDExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSourceeNBIDExtIEsValueValidateS1APIEContainer(fields s11.SourceeNBIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSourceeNBIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSourceeNBIDExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSourceeNBIDExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APIEContainer(fields s11.SubscriptionBasedUEDifferentiationInfoExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSupportedTAsItemExtIEsValueValidateS1APIEContainer(fields s11.SupportedTAsItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSupportedTAsItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSupportedTAsItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSupportedTAsItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSynchronisationInformationExtIEsValueValidateS1APIEContainer(fields s11.SynchronisationInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSynchronisationInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSynchronisationInformationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSynchronisationInformationExtIEsValueMethodRule(field.Value).Assignment
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

// ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ConnectionEstablishmentIndicationIEValueERABIEContainerList].
type ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueERABIEContainerList, error)
	encode  func(ConnectionEstablishmentIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) New(value ConnectionEstablishmentIndicationIEValueERABIEContainerList) (ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value ConnectionEstablishmentIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ConnectionEstablishmentIndicationIEs}} of TS 36.413: a list of information element fields.
type ConnectionEstablishmentIndicationIEValueERABIEContainerList []ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APERABIEContainerList(v *ConnectionEstablishmentIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APERABIEContainerList(v *ConnectionEstablishmentIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APERABIEContainerList(v *s11.SensorNameConfigExtIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s30.BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// sourceNodeIDExtensionIEIEValueProtocolOpenValue is the concrete protocolOpenValue[SourceNodeIDExtensionIEIEValue].
type SourceNodeIDExtensionIEIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SourceNodeIDExtensionIEIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SourceNodeIDExtensionIEIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APERABIEContainerList(v *s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APERABIEContainerList(v *s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEInformationTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEInformationTransferIEValueERABIEContainerList].
type UEInformationTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEValueERABIEContainerList, error)
	encode  func(UEInformationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEValueERABIEContainerList, aper.DecodeState) (UEInformationTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEInformationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) New(value UEInformationTransferIEValueERABIEContainerList) (UEInformationTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value UEInformationTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEInformationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) encodeChanged(value UEInformationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEInformationTransferIEs}} of TS 36.413: a list of information element fields.
type UEInformationTransferIEValueERABIEContainerList []UEInformationTransferIEValueProtocolIESingleContainer

// ConnectionEstablishmentIndicationIEFieldValueCodec is the concrete ValueCodec[ConnectionEstablishmentIndicationIEField].
type ConnectionEstablishmentIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEField, error)
	encode  func(ConnectionEstablishmentIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndicationIEField, aper.DecodeState) (ConnectionEstablishmentIndicationIEField, aper.Snapshot)
	compare func(ConnectionEstablishmentIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationIEFieldValueCodec) New(value ConnectionEstablishmentIndicationIEField) (ConnectionEstablishmentIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationIEFieldValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationIEFieldValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationIEFieldValueCodec) encodeChanged(value ConnectionEstablishmentIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEField(v *s11.SourceNodeIDExtensionIEIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s06.BridgeSourceNodeIDExtensionIEIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s11.BridgeSourceNodeIDExtensionIEIEFieldFieldReplay(v), *s11.BridgeSourceNodeIDExtensionIEIEFieldFieldWithoutReplay(v))
}
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEField(v *s11.SourceNodeIDExtensionIEIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSourceNodeIDExtensionIEIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s11.BridgeSourceNodeIDExtensionIEIEFieldFieldReplay(v), *s11.BridgeSourceNodeIDExtensionIEIEFieldFieldWithoutReplay(v))
}

// UEInformationTransferIEFieldValueCodec is the concrete ValueCodec[UEInformationTransferIEField].
type UEInformationTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEField, error)
	encode  func(UEInformationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEField, aper.DecodeState) (UEInformationTransferIEField, aper.Snapshot)
	compare func(UEInformationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEFieldValueCodec) New(value UEInformationTransferIEField) (UEInformationTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEFieldValueCodec) EncodeAPER(value UEInformationTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEFieldValueCodec) encodeBudgetValue(value UEInformationTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEFieldValueCodec) encodeChanged(value UEInformationTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationIEContainerValueCodec is the concrete ValueCodec[ConnectionEstablishmentIndicationIEContainer].
type ConnectionEstablishmentIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEContainer, error)
	encode  func(ConnectionEstablishmentIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndicationIEContainer, aper.DecodeState) (ConnectionEstablishmentIndicationIEContainer, aper.Snapshot)
	compare func(ConnectionEstablishmentIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationIEContainerValueCodec) New(value ConnectionEstablishmentIndicationIEContainer) (ConnectionEstablishmentIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationIEContainerValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationIEContainerValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationIEContainerValueCodec) encodeChanged(value ConnectionEstablishmentIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEContainer(v *s11.SourceNodeIDExtensionIEIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainer(v *s11.SourceNodeIDExtensionIEIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEInformationTransferIEContainerValueCodec is the concrete ValueCodec[UEInformationTransferIEContainer].
type UEInformationTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEContainer, error)
	encode  func(UEInformationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEContainer, aper.DecodeState) (UEInformationTransferIEContainer, aper.Snapshot)
	compare func(UEInformationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEContainerValueCodec) New(value UEInformationTransferIEContainer) (UEInformationTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEContainerValueCodec) EncodeAPER(value UEInformationTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEContainerValueCodec) encodeBudgetValue(value UEInformationTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEContainerValueCodec) encodeChanged(value UEInformationTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList].
type ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ConnectionEstablishmentIndicationIEs}} of TS 36.413: a list of information element fields.
type ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList []ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolErrorIEContainerList(v *s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s30.BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolErrorIEContainerList(v *s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(v *s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEInformationTransferIEValueProtocolErrorIEContainerList].
type UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(UEInformationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) New(value UEInformationTransferIEValueProtocolErrorIEContainerList) (UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEInformationTransferIEs}} of TS 36.413: a list of information element fields.
type UEInformationTransferIEValueProtocolErrorIEContainerList []UEInformationTransferIEValueProtocolIESingleContainer

// ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ConnectionEstablishmentIndicationIEValueProtocolIEContainerList].
type ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, error)
	encode  func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) New(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerList) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ConnectionEstablishmentIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ConnectionEstablishmentIndicationIEValueProtocolIEContainerList []ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainerList(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainerList(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainerList(v *s11.SensorNameConfigExtIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s30.BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEContainerList(v *s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainerList(v *s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEInformationTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEInformationTransferIEValueProtocolIEContainerList].
type UEInformationTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEValueProtocolIEContainerList, error)
	encode  func(UEInformationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEValueProtocolIEContainerList, aper.DecodeState) (UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) New(value UEInformationTransferIEValueProtocolIEContainerList) (UEInformationTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEInformationTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEInformationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEInformationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEInformationTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEInformationTransferIEValueProtocolIEContainerList []UEInformationTransferIEValueProtocolIESingleContainer

// ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ConnectionEstablishmentIndicationIEValueERABIEContainerList].
type ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectionEstablishmentIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ConnectionEstablishmentIndicationIEs}} of TS 36.413: a single information element field.
type ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer = ConnectionEstablishmentIndicationIEField

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIESingleContainer(v *ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIESingleContainer(v *ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIESingleContainer(v *s11.SourceNodeIDExtensionIEIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIESingleContainer(v *s11.SourceNodeIDExtensionIEIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEInformationTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[UEInformationTransferIEValueERABIEContainerList].
type UEInformationTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEValueERABIEContainerListAPERValue) WithoutReplay() UEInformationTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEInformationTransferIEs}} of TS 36.413: a single information element field.
type UEInformationTransferIEValueProtocolIESingleContainer = UEInformationTransferIEField

// ConnectionEstablishmentIndicationIEFieldAPERValue is the concrete APERValue[ConnectionEstablishmentIndicationIEField].
type ConnectionEstablishmentIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectionEstablishmentIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationIEFieldAPERValue) WithoutReplay() ConnectionEstablishmentIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEFieldAPERValue is the concrete APERValue[UEInformationTransferIEField].
type UEInformationTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEFieldAPERValue) WithoutReplay() UEInformationTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationIEContainerAPERValue is the concrete APERValue[ConnectionEstablishmentIndicationIEContainer].
type ConnectionEstablishmentIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectionEstablishmentIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationIEContainerAPERValue) WithoutReplay() ConnectionEstablishmentIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEContainerAPERValue is the concrete APERValue[UEInformationTransferIEContainer].
type UEInformationTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEContainerAPERValue) WithoutReplay() UEInformationTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList].
type ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEInformationTransferIEValueProtocolErrorIEContainerList].
type UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ConnectionEstablishmentIndicationIEValueProtocolIEContainerList].
type ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectionEstablishmentIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEInformationTransferIEValueProtocolIEContainerList].
type UEInformationTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEInformationTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APConnectedengNBItem(v *ConnectedengNBItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEnGNBID(&v.EnGNBID, s)
	BridgeCaptureS1APSupportedTAs(&v.SupportedTAs, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APConnectedengNBItem(v *ConnectedengNBItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEnGNBID(&v.EnGNBID, s)
	BridgeCompareS1APSupportedTAs(&v.SupportedTAs, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APConnectedengNBList(v *ConnectedengNBList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APConnectedengNBItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APConnectedengNBList(v *ConnectedengNBList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APConnectedengNBItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APConnectionEstablishmentIndication(v *ConnectionEstablishmentIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APConnectionEstablishmentIndication(v *ConnectionEstablishmentIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APConnectionEstablishmentIndicationIEValue(v *ConnectionEstablishmentIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s00.BridgeCaptureS1APUERadioCapability(v.rowUERadioCapability, s)
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
		case s00.ProtocolIEID(253):
			{
				f := s.Begin()
				s.Bool(v.rowDLCPSecurityInformation == nil)
				if v.rowDLCPSecurityInformation != nil {
					s15.BridgeCaptureS1APDLCPSecurityInformation(v.rowDLCPSecurityInformation, s)
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
		case s00.ProtocolIEID(280):
			{
				f := s.Begin()
				s.Bool(v.rowEndIndication == nil)
				if v.rowEndIndication != nil {
					s00.BridgeCaptureS1APEndIndication(v.rowEndIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(252):
			{
				f := s.Begin()
				s.Bool(v.rowUELevelQoSParameters == nil)
				if v.rowUELevelQoSParameters != nil {
					s18.BridgeCaptureS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
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
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s00.BridgeCaptureS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(354):
			{
				f := s.Begin()
				s.Bool(v.rowCoarseUELocation == nil)
				if v.rowCoarseUELocation != nil {
					s00.BridgeCaptureS1APCoarseUELocation(v.rowCoarseUELocation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ConnectionEstablishmentIndicationIEValue) captureSemantics(s aper.SemanticCapture) ConnectionEstablishmentIndicationIEValue {
	BridgeCaptureS1APConnectionEstablishmentIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APConnectionEstablishmentIndicationIEValue(v *ConnectionEstablishmentIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s07.BridgeCompareS1APUERadioCapability(v.rowUERadioCapability, s)
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
		case s00.ProtocolIEID(253):
			{
				f := s.Begin()
				s.Bool(v.rowDLCPSecurityInformation == nil)
				if v.rowDLCPSecurityInformation != nil {
					s15.BridgeCompareS1APDLCPSecurityInformation(v.rowDLCPSecurityInformation, s)
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
		case s00.ProtocolIEID(280):
			{
				f := s.Begin()
				s.Bool(v.rowEndIndication == nil)
				if v.rowEndIndication != nil {
					s02.BridgeCompareS1APEndIndication(v.rowEndIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(252):
			{
				f := s.Begin()
				s.Bool(v.rowUELevelQoSParameters == nil)
				if v.rowUELevelQoSParameters != nil {
					s18.BridgeCompareS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
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
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s02.BridgeCompareS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(354):
			{
				f := s.Begin()
				s.Bool(v.rowCoarseUELocation == nil)
				if v.rowCoarseUELocation != nil {
					s02.BridgeCompareS1APCoarseUELocation(v.rowCoarseUELocation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ConnectionEstablishmentIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APConnectionEstablishmentIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSensorMeasConfigNameItem(v *SensorMeasConfigNameItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCaptureS1APSensorNameConfig(&v.SensorNameConfig, s)
	s.Bool(v.IEExtensions == nil)
	s30.BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSensorMeasConfigNameItem(v *SensorMeasConfigNameItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCompareS1APSensorNameConfig(&v.SensorNameConfig, s)
	s.Bool(v.IEExtensions == nil)
	s30.BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSensorMeasConfigNameList(v *SensorMeasConfigNameList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APSensorMeasConfigNameItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APSensorMeasConfigNameList(v *SensorMeasConfigNameList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APSensorMeasConfigNameItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSensorMeasurementConfiguration(v *SensorMeasurementConfiguration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APSensorMeasConfig(&v.SensorMeasConfig, s)
	s.Bool(v.SensorMeasConfigNameList == nil)
	BridgeCaptureS1APSensorMeasConfigNameList(&v.SensorMeasConfigNameList, s)
	s.Bool(v.IEExtensions == nil)
	s30.BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSensorMeasurementConfiguration(v *SensorMeasurementConfiguration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APSensorMeasConfig(&v.SensorMeasConfig, s)
	s.Bool(v.SensorMeasConfigNameList == nil)
	BridgeCompareS1APSensorMeasConfigNameList(&v.SensorMeasConfigNameList, s)
	s.Bool(v.IEExtensions == nil)
	s30.BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APServedDCNs(v *ServedDCNs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APServedDCNsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APServedDCNs(v *ServedDCNs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APServedDCNsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APServedDCNsItem(v *ServedDCNsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APDCNID(&v.DCNID, s)
	s00.BridgeCaptureS1APRelativeMMECapacity(&v.RelativeDCNCapacity, s)
	s.Bool(v.IEExtensions == nil)
	BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APServedDCNsItem(v *ServedDCNsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APDCNID(&v.DCNID, s)
	s06.BridgeCompareS1APRelativeMMECapacity(&v.RelativeDCNCapacity, s)
	s.Bool(v.IEExtensions == nil)
	BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APServedGUMMEIs(v *ServedGUMMEIs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APServedGUMMEIsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APServedGUMMEIs(v *ServedGUMMEIs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APServedGUMMEIsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APServedGUMMEIsItem(v *ServedGUMMEIsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APServedPLMNs(&v.ServedPLMNs, s)
	s00.BridgeCaptureS1APServedGroupIDs(&v.ServedGroupIDs, s)
	s00.BridgeCaptureS1APServedMMECs(&v.ServedMMECs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APServedGUMMEIsItem(v *ServedGUMMEIsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APServedPLMNs(&v.ServedPLMNs, s)
	s07.BridgeCompareS1APServedGroupIDs(&v.ServedGroupIDs, s)
	s07.BridgeCompareS1APServedMMECs(&v.ServedMMECs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSourceNgRanNodeID(v *SourceNgRanNodeID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s19.BridgeCaptureS1APGlobalRANNODEID(&v.GlobalRANNODEID, s)
	s18.BridgeCaptureS1APFiveGSTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSourceNgRanNodeID(v *SourceNgRanNodeID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s19.BridgeCompareS1APGlobalRANNODEID(&v.GlobalRANNODEID, s)
	s18.BridgeCompareS1APFiveGSTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSourceNodeID(v *SourceNodeID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.SourceNodeIDChoiceSourceNgRanNodeID:
		{
			f := s.Begin()
			s.Bool(v.SourceNgRanNodeID == nil)
			if v.SourceNgRanNodeID != nil {
				BridgeCaptureS1APSourceNgRanNodeID(v.SourceNgRanNodeID, s)
			}
			s.End(f, nil, false)
		}
	case s00.SourceNodeIDChoiceSourceNodeIDExtension:
		{
			f := s.Begin()
			s.Bool(v.SourceNodeIDExtension == nil)
			if v.SourceNodeIDExtension != nil {
				s20.BridgeCaptureS1APSourceNodeIDExtension(v.SourceNodeIDExtension, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSourceNodeID(v *SourceNodeID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.SourceNodeIDChoiceSourceNgRanNodeID:
		{
			f := s.Begin()
			s.Bool(v.SourceNgRanNodeID == nil)
			if v.SourceNgRanNodeID != nil {
				BridgeCompareS1APSourceNgRanNodeID(v.SourceNgRanNodeID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SourceNodeIDChoiceSourceNodeIDExtension:
		{
			f := s.Begin()
			s.Bool(v.SourceNodeIDExtension == nil)
			if v.SourceNodeIDExtension != nil {
				s20.BridgeCompareS1APSourceNodeIDExtension(v.SourceNodeIDExtension, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v *SubscriptionBasedUEDifferentiationInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.PeriodicCommunicationIndicator == nil)
		if v.PeriodicCommunicationIndicator != nil {
			s.Int(int64((*v.PeriodicCommunicationIndicator)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.PeriodicTime)
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ScheduledCommunicationTime == nil)
		if v.ScheduledCommunicationTime != nil {
			s28.BridgeCaptureS1APScheduledCommunicationTime(v.ScheduledCommunicationTime, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.StationaryIndication == nil)
		if v.StationaryIndication != nil {
			s.Int(int64((*v.StationaryIndication)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TrafficProfile == nil)
		if v.TrafficProfile != nil {
			s.Int(int64((*v.TrafficProfile)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.BatteryIndication == nil)
		if v.BatteryIndication != nil {
			s.Int(int64((*v.BatteryIndication)))
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v *SubscriptionBasedUEDifferentiationInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.PeriodicCommunicationIndicator == nil)
		if v.PeriodicCommunicationIndicator != nil {
			s.Int(int64((*v.PeriodicCommunicationIndicator)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.PeriodicTime)
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ScheduledCommunicationTime == nil)
		if v.ScheduledCommunicationTime != nil {
			s28.BridgeCompareS1APScheduledCommunicationTime(v.ScheduledCommunicationTime, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.StationaryIndication == nil)
		if v.StationaryIndication != nil {
			s.Int(int64((*v.StationaryIndication)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TrafficProfile == nil)
		if v.TrafficProfile != nil {
			s.Int(int64((*v.TrafficProfile)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.BatteryIndication == nil)
		if v.BatteryIndication != nil {
			s.Int(int64((*v.BatteryIndication)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSupportedTAs(v *SupportedTAs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APSupportedTAsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APSupportedTAs(v *SupportedTAs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APSupportedTAsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSupportedTAsItem(v *SupportedTAsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTAC(&v.TAC, s)
	s00.BridgeCaptureS1APBPLMNs(&v.BroadcastPLMNs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSupportedTAsItem(v *SupportedTAsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTAC(&v.TAC, s)
	s07.BridgeCompareS1APBPLMNs(&v.BroadcastPLMNs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSynchronisationInformation(v *SynchronisationInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APStratumLevel(&v.SourceStratumLevel, s)
	{
		f := s.Begin()
		s.Bool(v.ListeningSubframePattern == nil)
		if v.ListeningSubframePattern != nil {
			s19.BridgeCaptureS1APListeningSubframePattern(v.ListeningSubframePattern, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.AggressoreCGIList == nil)
	s21.BridgeCaptureS1APIEsECGIList(&v.AggressoreCGIList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSynchronisationInformation(v *SynchronisationInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APStratumLevel(&v.SourceStratumLevel, s)
	{
		f := s.Begin()
		s.Bool(v.ListeningSubframePattern == nil)
		if v.ListeningSubframePattern != nil {
			s19.BridgeCompareS1APListeningSubframePattern(v.ListeningSubframePattern, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.AggressoreCGIList == nil)
	s24.BridgeCompareS1APIEsECGIList(&v.AggressoreCGIList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEInformationTransferIEValue(v *UEInformationTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s28.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(252):
			{
				f := s.Begin()
				s.Bool(v.rowUELevelQoSParameters == nil)
				if v.rowUELevelQoSParameters != nil {
					s18.BridgeCaptureS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s00.BridgeCaptureS1APUERadioCapability(v.rowUERadioCapability, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
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
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s00.BridgeCaptureS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEInformationTransferIEValue) captureSemantics(s aper.SemanticCapture) UEInformationTransferIEValue {
	BridgeCaptureS1APUEInformationTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEInformationTransferIEValue(v *UEInformationTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s28.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(252):
			{
				f := s.Begin()
				s.Bool(v.rowUELevelQoSParameters == nil)
				if v.rowUELevelQoSParameters != nil {
					s18.BridgeCompareS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s07.BridgeCompareS1APUERadioCapability(v.rowUERadioCapability, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
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
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s02.BridgeCompareS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEInformationTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEInformationTransferIEValue(&v, &s)
	return s
}

type ConnectedengNBList = []ConnectedengNBItem

// ConnectedengNBItem represents the ASN.1 type ConnectedengNBItem (SEQUENCE).
type ConnectedengNBItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	EnGNBID           s00.EnGNBID                              `asn1:"tag:0,context,implicit"`
	SupportedTAs      SupportedTAs                             `asn1:"tag:1,context,implicit"`
	supportedTAsIndef bool                                     `asn1:"-" json:"-"`
	IEExtensions      s07.ConnectedengNBItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                     `asn1:"-" json:"-"`
	extCount          int64                                    `asn1:"-" json:"-"`
	extPresent        []bool                                   `asn1:"-" json:"-"`
	extData           [][]byte                                 `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ServedDCNs = []ServedDCNsItem

// ServedDCNsItem represents the ASN.1 type ServedDCNsItem (SEQUENCE).
type ServedDCNsItem struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	DCNID               s00.DCNID                            `asn1:"tag:0,context,implicit"`
	RelativeDCNCapacity s00.RelativeMMECapacity              `asn1:"tag:1,context,implicit"`
	IEExtensions        s11.ServedDCNsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                 `asn1:"-" json:"-"`
	extCount            int64                                `asn1:"-" json:"-"`
	extPresent          []bool                               `asn1:"-" json:"-"`
	extData             [][]byte                             `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// SensorMeasConfigNameItem represents the ASN.1 type SensorMeasConfigNameItem (SEQUENCE).
type SensorMeasConfigNameItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	SensorNameConfig  s30.SensorNameConfig                           `asn1:"tag:0,context,explicit"`
	IEExtensions      s11.SensorMeasConfigNameItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                           `asn1:"-" json:"-"`
	extCount          int64                                          `asn1:"-" json:"-"`
	extPresent        []bool                                         `asn1:"-" json:"-"`
	extData           [][]byte                                       `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type SensorMeasConfigNameList = []SensorMeasConfigNameItem

// SensorMeasurementConfiguration represents the ASN.1 type SensorMeasurementConfiguration (SEQUENCE).
type SensorMeasurementConfiguration struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	received                      bool
	withoutReplay                 bool
	receivedAbsolute              bool
	receivedBytes                 aper.WireSpan
	receivedLocation              aper.Location
	SensorMeasConfig              s00.SensorMeasConfig                                 `asn1:"tag:0,context,implicit"`
	SensorMeasConfigNameList      SensorMeasConfigNameList                             `asn1:"tag:1,context,implicit,optional" json:"SensorMeasConfigNameList,omitzero"`
	sensorMeasConfigNameListIndef bool                                                 `asn1:"-" json:"-"`
	IEExtensions                  s11.SensorMeasurementConfigurationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                                                 `asn1:"-" json:"-"`
	extCount                      int64                                                `asn1:"-" json:"-"`
	extPresent                    []bool                                               `asn1:"-" json:"-"`
	extData                       [][]byte                                             `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                                    `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding                               `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
}

// NewSensorNameConfigUncompensatedBarometricConfig creates a SensorNameConfig with the uncompensatedBarometricConfig alternative.
func BridgeNewSensorNameConfigUncompensatedBarometricConfigLegacy(v int64) s30.SensorNameConfig {
	return s30.SensorNameConfig{
		Choice:                        s00.SensorNameConfigChoiceUncompensatedBarometricConfig,
		UncompensatedBarometricConfig: &v,
	}
}

// NewSensorNameConfigChoiceExtensions creates a SensorNameConfig with the choice-Extensions alternative.
func BridgeNewSensorNameConfigChoiceExtensionsLegacy(v s11.SensorNameConfigExtIEValueProtocolIESingleContainer) s30.SensorNameConfig {
	return s30.SensorNameConfig{
		Choice:           s00.SensorNameConfigChoiceChoiceExtensions,
		ChoiceExtensions: &v,
	}
}

// SynchronisationInformation represents the ASN.1 type SynchronisationInformation (SEQUENCE).
type SynchronisationInformation struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	SourceStratumLevel       s00.StratumLevel                                 `asn1:"tag:0,context,implicit,optional" json:"SourceStratumLevel,omitzero"`
	ListeningSubframePattern *s19.ListeningSubframePattern                    `asn1:"tag:1,context,implicit,optional" json:"ListeningSubframePattern,omitempty"`
	AggressoreCGIList        s18.IEsECGIList                                  `asn1:"tag:2,context,implicit,optional" json:"AggressoreCGIList,omitzero"`
	aggressoreCGIListIndef   bool                                             `asn1:"-" json:"-"`
	IEExtensions             s11.SynchronisationInformationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                             `asn1:"-" json:"-"`
	extCount                 int64                                            `asn1:"-" json:"-"`
	extPresent               []bool                                           `asn1:"-" json:"-"`
	extData                  [][]byte                                         `asn1:"-" json:"-"`
	perPadding               aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding            []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin                []aper.OpaqueOrigin
	extWire                  []aper.WireSpan
}

// SourceNodeID represents the ASN.1 CHOICE type SourceNodeID.
type SourceNodeID struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	Choice                int
	perPadding            aper.CompletePadding       `json:"-"`
	perOpenTypePadding    aper.CompletePadding       `json:"-"`
	SourceNgRanNodeID     *SourceNgRanNodeID         `json:"SourceNgRanNodeID,omitempty"`
	SourceNodeIDExtension *s20.SourceNodeIDExtension `json:"SourceNodeIDExtension,omitempty"`
}

// NewSourceNodeIDSourceNgRanNodeID creates a SourceNodeID with the sourceNgRanNode-ID alternative.
func BridgeNewSourceNodeIDSourceNgRanNodeIDLegacy(v SourceNgRanNodeID) SourceNodeID {
	return SourceNodeID{
		Choice:            s00.SourceNodeIDChoiceSourceNgRanNodeID,
		SourceNgRanNodeID: &v,
	}
}

// NewSourceNodeIDSourceNodeIDExtension creates a SourceNodeID with the sourceNodeID-Extension alternative.
func BridgeNewSourceNodeIDSourceNodeIDExtensionLegacy(v s20.SourceNodeIDExtension) SourceNodeID {
	return SourceNodeID{
		Choice:                s00.SourceNodeIDChoiceSourceNodeIDExtension,
		SourceNodeIDExtension: &v,
	}
}

// SourceNgRanNodeID represents the ASN.1 type SourceNgRanNode-ID (SEQUENCE).
type SourceNgRanNodeID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobalRANNODEID   s19.GlobalRANNODEID                     `asn1:"tag:0,context,explicit"`
	SelectedTAI       s18.FiveGSTAI                           `asn1:"tag:1,context,implicit"`
	IEExtensions      s11.SourceNgRanNodeIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                    `asn1:"-" json:"-"`
	extCount          int64                                   `asn1:"-" json:"-"`
	extPresent        []bool                                  `asn1:"-" json:"-"`
	extData           [][]byte                                `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ServedGUMMEIs = []ServedGUMMEIsItem

// ServedGUMMEIsItem represents the ASN.1 type ServedGUMMEIsItem (SEQUENCE).
type ServedGUMMEIsItem struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	ServedPLMNs         s00.ServedPLMNs                         `asn1:"tag:0,context,implicit"`
	servedPLMNsIndef    bool                                    `asn1:"-" json:"-"`
	ServedGroupIDs      s00.ServedGroupIDs                      `asn1:"tag:1,context,implicit"`
	servedGroupIDsIndef bool                                    `asn1:"-" json:"-"`
	ServedMMECs         s00.ServedMMECs                         `asn1:"tag:2,context,implicit"`
	servedMMECsIndef    bool                                    `asn1:"-" json:"-"`
	IEExtensions        s11.ServedGUMMEIsItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                    `asn1:"-" json:"-"`
	extCount            int64                                   `asn1:"-" json:"-"`
	extPresent          []bool                                  `asn1:"-" json:"-"`
	extData             [][]byte                                `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// SubscriptionBasedUEDifferentiationInfo represents the ASN.1 type Subscription-Based-UE-DifferentiationInfo (SEQUENCE).
type SubscriptionBasedUEDifferentiationInfo struct {
	replay                         aper.Snapshot
	stream                         aper.WireSpan
	received                       bool
	withoutReplay                  bool
	receivedAbsolute               bool
	receivedBytes                  aper.WireSpan
	receivedLocation               aper.Location
	PeriodicCommunicationIndicator *int64                                                       `asn1:"tag:0,context,implicit,optional" json:"PeriodicCommunicationIndicator,omitempty"`
	PeriodicTime                   *big.Int                                                     `asn1:"tag:1,context,implicit,optional" json:"PeriodicTime,omitempty"`
	ScheduledCommunicationTime     *s28.ScheduledCommunicationTime                              `asn1:"tag:2,context,implicit,optional" json:"ScheduledCommunicationTime,omitempty"`
	StationaryIndication           *int64                                                       `asn1:"tag:3,context,implicit,optional" json:"StationaryIndication,omitempty"`
	TrafficProfile                 *int64                                                       `asn1:"tag:4,context,implicit,optional" json:"TrafficProfile,omitempty"`
	BatteryIndication              *int64                                                       `asn1:"tag:5,context,implicit,optional" json:"BatteryIndication,omitempty"`
	IEExtensions                   s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer `asn1:"tag:6,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                                         `asn1:"-" json:"-"`
	extCount                       int64                                                        `asn1:"-" json:"-"`
	extPresent                     []bool                                                       `asn1:"-" json:"-"`
	extData                        [][]byte                                                     `asn1:"-" json:"-"`
	perPadding                     aper.FinalPadding                                            `asn1:"-" json:"-"`
	perExtPadding                  []aper.CompletePadding                                       `asn1:"-" json:"-"`
	extOrigin                      []aper.OpaqueOrigin
	extWire                        []aper.WireSpan
}
type SupportedTAs = []SupportedTAsItem

// SupportedTAsItem represents the ASN.1 type SupportedTAs-Item (SEQUENCE).
type SupportedTAsItem struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	TAC                 s00.TAC                                `asn1:"tag:0,context,implicit"`
	BroadcastPLMNs      s00.BPLMNs                             `asn1:"tag:1,context,implicit"`
	broadcastPLMNsIndef bool                                   `asn1:"-" json:"-"`
	IEExtensions        s11.SupportedTAsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                   `asn1:"-" json:"-"`
	extCount            int64                                  `asn1:"-" json:"-"`
	extPresent          []bool                                 `asn1:"-" json:"-"`
	extData             [][]byte                               `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}
type BridgeAsn1cAPERConnectedengNBListListValue struct{ Value ConnectedengNBList }

// MarshalAPERConnectedengNBListTo appends a ConnectedengNBList list to bb.
func BridgeMarshalAPERConnectedengNBListTo(list ConnectedengNBList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERConnectedengNBListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ConnectedengNBItem to APER format.
func (v *ConnectedengNBItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ConnectedengNBItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAlignedExt(bb, v.EnGNBID.Bytes, v.EnGNBID.BitLength, 22, 32, true, true); err != nil {
		return fmt.Errorf("encoding en-gNB-ID: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.SupportedTAs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_supportedtas, fragmentLength_supportedtas int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_supportedtas < 0 || fragmentOffset_supportedtas > int64(len(v.SupportedTAs)) || fragmentLength_supportedtas < 0 || fragmentLength_supportedtas > int64(len(v.SupportedTAs[fragmentOffset_supportedtas:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.SupportedTAs[fragmentOffset_supportedtas : fragmentOffset_supportedtas+fragmentLength_supportedtas] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding supportedTAs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding supportedTAs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeConnectedengNBItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ConnectedengNBItem from APER format.
func (v *ConnectedengNBItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ConnectedengNBItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ConnectedengNBItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBItem")
	}
	bb.EnterComponent("ConnectedengNBItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ConnectedengNBItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ConnectedengNBItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ConnectedengNBItem{}
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
	bsBytes_engnbid, bsBitLen_engnbid, err := aper.DecodeBitStringAlignedExt(bb, 22, 32, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EnGNBID")
	}
	v.EnGNBID = runtime.BitString{Bytes: bsBytes_engnbid, BitLength: bsBitLen_engnbid}
	toleranceMark_supportedtas := bb.EnterComponent("SupportedTAs")
	v.SupportedTAs = make(SupportedTAs, 0)
	_, errCollection_supportedtas := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_supportedtas, fragmentLength_supportedtas int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_supportedtas < 0 || fragmentLength_supportedtas < 0 || fragmentLength_supportedtas > int64(^uint(0)>>1) || fragmentOffset_supportedtas > int64(^uint(0)>>1)-fragmentLength_supportedtas {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_supportedtas; i++ {
			var elem SupportedTAsItem
			elementMark := bb.EnterIndex(fragmentOffset_supportedtas + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("SupportedTAs[%d]", fragmentOffset_supportedtas+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.SupportedTAs, elem); err != nil {
				return err
			} else {
				v.SupportedTAs = next
			}
		}
		return nil
	})
	if errCollection_supportedtas != nil {
		return runtime.WrapDecodePath(errCollection_supportedtas, "SupportedTAs")
	}
	bb.LeaveComponent(toleranceMark_supportedtas)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.ConnectedengNBItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.ConnectedengNBItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeConnectedengNBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERServedDCNsListValue struct{ Value ServedDCNs }

// MarshalAPERServedDCNsTo appends a ServedDCNs list to bb.
func BridgeMarshalAPERServedDCNsTo(list ServedDCNs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERServedDCNsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ServedDCNsItem to APER format.
func (v *ServedDCNsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ServedDCNsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.DCNID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding dCN-ID: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.RelativeDCNCapacity), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding relativeDCNCapacity: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeServedDCNsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ServedDCNsItem from APER format.
func (v *ServedDCNsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ServedDCNsItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ServedDCNsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ServedDCNsItem")
	}
	bb.EnterComponent("ServedDCNsItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ServedDCNsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ServedDCNsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedDCNsItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ServedDCNsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ServedDCNsItem{}
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
	val_dcnid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "DCNID")
	}
	v.DCNID = s00.DCNID(val_dcnid)
	val_relativedcncapacity, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RelativeDCNCapacity")
	}
	v.RelativeDCNCapacity = s00.RelativeMMECapacity(val_relativedcncapacity)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.ServedDCNsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.ServedDCNsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SensorMeasConfigNameItem to APER format.
func (v *SensorMeasConfigNameItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SensorMeasConfigNameItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s30.BridgeSensorNameConfigMethodMarshalAPERTo(&v.SensorNameConfig, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding sensorNameConfig: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SensorMeasConfigNameItem from APER format.
func (v *SensorMeasConfigNameItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SensorMeasConfigNameItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SensorMeasConfigNameItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasConfigNameItem")
	}
	bb.EnterComponent("SensorMeasConfigNameItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasConfigNameItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "SensorMeasConfigNameItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasConfigNameItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SensorMeasConfigNameItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorMeasConfigNameItem{}
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
	toleranceMark_sensornameconfig := bb.EnterComponent("SensorNameConfig")
	if err := s30.BridgeSensorNameConfigMethodUnmarshalAPERFrom(&v.SensorNameConfig, bb); err != nil {
		return runtime.WrapDecodePath(err, "SensorNameConfig")
	}
	bb.LeaveComponent(toleranceMark_sensornameconfig)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.SensorMeasConfigNameItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SensorMeasConfigNameItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERSensorMeasConfigNameListListValue struct{ Value SensorMeasConfigNameList }

// MarshalAPERSensorMeasConfigNameListTo appends a SensorMeasConfigNameList list to bb.
func BridgeMarshalAPERSensorMeasConfigNameListTo(list SensorMeasConfigNameList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERSensorMeasConfigNameListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 3, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes SensorMeasurementConfiguration to APER format.
func (v *SensorMeasurementConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SensorMeasurementConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.SensorMeasConfigNameList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SensorMeasConfig), 1, true); err != nil {
		return fmt.Errorf("encoding sensorMeasConfig: %w", err)
	}
	if v.SensorMeasConfigNameList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.SensorMeasConfigNameList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 3, HasUpper: true}, true, func(fragmentOffset_sensormeasconfignamelist, fragmentLength_sensormeasconfignamelist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_sensormeasconfignamelist < 0 || fragmentOffset_sensormeasconfignamelist > int64(len(v.SensorMeasConfigNameList)) || fragmentLength_sensormeasconfignamelist < 0 || fragmentLength_sensormeasconfignamelist > int64(len(v.SensorMeasConfigNameList[fragmentOffset_sensormeasconfignamelist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.SensorMeasConfigNameList[fragmentOffset_sensormeasconfignamelist : fragmentOffset_sensormeasconfignamelist+fragmentLength_sensormeasconfignamelist] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding sensorMeasConfigNameList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sensorMeasConfigNameList: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SensorMeasurementConfiguration from APER format.
func (v *SensorMeasurementConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SensorMeasurementConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SensorMeasurementConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasurementConfiguration")
	}
	bb.EnterComponent("SensorMeasurementConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasurementConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "SensorMeasurementConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasurementConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SensorMeasurementConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorMeasurementConfiguration{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_sensormeasconfignamelist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_sensormeasconfig, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SensorMeasConfig"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasConfig")
	}
	v.SensorMeasConfig = s00.SensorMeasConfig(val_sensormeasconfig)
	if opt_sensormeasconfignamelist {
		toleranceMark_sensormeasconfignamelist := bb.EnterComponent("SensorMeasConfigNameList")
		tmp_sensormeasconfignamelist := make(SensorMeasConfigNameList, 0)
		_, errCollection_sensormeasconfignamelist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 3, HasUpper: true}, true, func(fragmentOffset_sensormeasconfignamelist, fragmentLength_sensormeasconfignamelist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_sensormeasconfignamelist < 0 || fragmentLength_sensormeasconfignamelist < 0 || fragmentLength_sensormeasconfignamelist > int64(^uint(0)>>1) || fragmentOffset_sensormeasconfignamelist > int64(^uint(0)>>1)-fragmentLength_sensormeasconfignamelist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_sensormeasconfignamelist; i++ {
				var elem SensorMeasConfigNameItem
				elementMark := bb.EnterIndex(fragmentOffset_sensormeasconfignamelist + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("SensorMeasConfigNameList[%d]", fragmentOffset_sensormeasconfignamelist+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_sensormeasconfignamelist, elem); err != nil {
					return err
				} else {
					tmp_sensormeasconfignamelist = next
				}
			}
			return nil
		})
		if errCollection_sensormeasconfignamelist != nil {
			return runtime.WrapDecodePath(errCollection_sensormeasconfignamelist, "SensorMeasConfigNameList")
		}
		v.SensorMeasConfigNameList = tmp_sensormeasconfignamelist
		bb.LeaveComponent(toleranceMark_sensormeasconfignamelist)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.SensorMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SensorMeasurementConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SynchronisationInformation to APER format.
func (v *SynchronisationInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SynchronisationInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.SourceStratumLevel != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ListeningSubframePattern != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.AggressoreCGIList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.SourceStratumLevel != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.SourceStratumLevel, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound9, true); err != nil {
			return fmt.Errorf("encoding sourceStratumLevel: %w", err)
		}
	}
	if v.ListeningSubframePattern != nil {
		if err := s19.BridgeListeningSubframePatternMethodMarshalAPERTo(v.ListeningSubframePattern, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding listeningSubframePattern: %w", err)
		}
	}
	if v.AggressoreCGIList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.AggressoreCGIList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_aggressorecgilist, fragmentLength_aggressorecgilist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_aggressorecgilist < 0 || fragmentOffset_aggressorecgilist > int64(len(v.AggressoreCGIList)) || fragmentLength_aggressorecgilist < 0 || fragmentLength_aggressorecgilist > int64(len(v.AggressoreCGIList[fragmentOffset_aggressorecgilist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.AggressoreCGIList[fragmentOffset_aggressorecgilist : fragmentOffset_aggressorecgilist+fragmentLength_aggressorecgilist] {
				if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding aggressoreCGI-List element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding aggressoreCGI-List: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SynchronisationInformation from APER format.
func (v *SynchronisationInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SynchronisationInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SynchronisationInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SynchronisationInformation")
	}
	bb.EnterComponent("SynchronisationInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SynchronisationInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "SynchronisationInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "SynchronisationInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SynchronisationInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SynchronisationInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_sourcestratumlevel, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_listeningsubframepattern, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_aggressorecgilist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sourcestratumlevel {
		val_sourcestratumlevel, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound9, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "SourceStratumLevel")
		}
		v.SourceStratumLevel = val_sourcestratumlevel
	}
	if opt_listeningsubframepattern {
		toleranceMark_listeningsubframepattern := bb.EnterComponent("ListeningSubframePattern")
		var dec_listeningsubframepattern s19.ListeningSubframePattern
		if err := s19.BridgeListeningSubframePatternMethodUnmarshalAPERFrom(&dec_listeningsubframepattern, bb); err != nil {
			return runtime.WrapDecodePath(err, "ListeningSubframePattern")
		}
		if err := aper.ChargeValue(bb, dec_listeningsubframepattern); err != nil {
			return err
		}
		v.ListeningSubframePattern = &dec_listeningsubframepattern
		bb.LeaveComponent(toleranceMark_listeningsubframepattern)
	}
	if opt_aggressorecgilist {
		toleranceMark_aggressorecgilist := bb.EnterComponent("AggressoreCGIList")
		tmp_aggressorecgilist := make(s18.IEsECGIList, 0)
		_, errCollection_aggressorecgilist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_aggressorecgilist, fragmentLength_aggressorecgilist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_aggressorecgilist < 0 || fragmentLength_aggressorecgilist < 0 || fragmentLength_aggressorecgilist > int64(^uint(0)>>1) || fragmentOffset_aggressorecgilist > int64(^uint(0)>>1)-fragmentLength_aggressorecgilist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_aggressorecgilist; i++ {
				var elem s17.EUTRANCGI
				elementMark := bb.EnterIndex(fragmentOffset_aggressorecgilist + i)
				if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("AggressoreCGIList[%d]", fragmentOffset_aggressorecgilist+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_aggressorecgilist, elem); err != nil {
					return err
				} else {
					tmp_aggressorecgilist = next
				}
			}
			return nil
		})
		if errCollection_aggressorecgilist != nil {
			return runtime.WrapDecodePath(errCollection_aggressorecgilist, "AggressoreCGIList")
		}
		v.AggressoreCGIList = tmp_aggressorecgilist
		bb.LeaveComponent(toleranceMark_aggressorecgilist)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.SynchronisationInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SynchronisationInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SourceNodeID to APER format.
func (v *SourceNodeID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SourceNodeID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "SourceNodeID:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.SourceNodeIDChoiceSourceNgRanNodeID:
		if v.SourceNgRanNodeID == nil {
			return fmt.Errorf("choice alternative sourceNgRanNode-ID is nil")
		}
		if err := v.SourceNgRanNodeID.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding sourceNgRanNode-ID: %w", err)
		}
	case s00.SourceNodeIDChoiceSourceNodeIDExtension:
		if v.SourceNodeIDExtension == nil {
			return fmt.Errorf("choice alternative sourceNodeID-Extension is nil")
		}
		if err := s20.BridgeSourceNodeIDExtensionMethodMarshalAPERTo(v.SourceNodeIDExtension, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding sourceNodeID-Extension: %w", err)
		}
	default:
		return fmt.Errorf("unknown SourceNodeID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SourceNodeID from APER format.
func (v *SourceNodeID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SourceNodeID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SourceNodeID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeID")
	}
	bb.EnterComponent("SourceNodeID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeID")
	}
	padding, err := aper.CaptureFinalBits(bb, "SourceNodeID")
	if err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SourceNodeID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceNodeID{}
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
	case s00.SourceNodeIDChoiceSourceNgRanNodeID:
		toleranceMark_sourcengrannodeid := bb.EnterComponent("SourceNgRanNodeID")
		var dec_sourcengrannodeid SourceNgRanNodeID
		if err := dec_sourcengrannodeid.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SourceNgRanNodeID")
		}
		if err := aper.ChargeValue(bb, dec_sourcengrannodeid); err != nil {
			return err
		}
		v.SourceNgRanNodeID = &dec_sourcengrannodeid
		bb.LeaveComponent(toleranceMark_sourcengrannodeid)
	case s00.SourceNodeIDChoiceSourceNodeIDExtension:
		toleranceMark_sourcenodeidextension := bb.EnterComponent("SourceNodeIDExtension")
		var dec_sourcenodeidextension s20.SourceNodeIDExtension
		if err := s20.BridgeSourceNodeIDExtensionMethodUnmarshalAPERFrom(&dec_sourcenodeidextension, bb); err != nil {
			return runtime.WrapDecodePath(err, "SourceNodeIDExtension")
		}
		if err := aper.ChargeValue(bb, dec_sourcenodeidextension); err != nil {
			return err
		}
		v.SourceNodeIDExtension = &dec_sourcenodeidextension
		bb.LeaveComponent(toleranceMark_sourcenodeidextension)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes SourceNgRanNodeID to APER format.
func (v *SourceNgRanNodeID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SourceNgRanNodeID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s19.BridgeGlobalRANNODEIDMethodMarshalAPERTo(&v.GlobalRANNODEID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-RAN-NODE-ID: %w", err)
	}
	if err := s18.BridgeFiveGSTAIMethodMarshalAPERTo(&v.SelectedTAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding selected-TAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SourceNgRanNodeID from APER format.
func (v *SourceNgRanNodeID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SourceNgRanNodeID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SourceNgRanNodeID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SourceNgRanNodeID")
	}
	bb.EnterComponent("SourceNgRanNodeID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceNgRanNodeID")
	}
	padding, err := aper.CaptureFinalBits(bb, "SourceNgRanNodeID")
	if err != nil {
		return runtime.WrapDecodePath(err, "SourceNgRanNodeID")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SourceNgRanNodeID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceNgRanNodeID{}
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
	toleranceMark_globalrannodeid := bb.EnterComponent("GlobalRANNODEID")
	if err := s19.BridgeGlobalRANNODEIDMethodUnmarshalAPERFrom(&v.GlobalRANNODEID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalRANNODEID")
	}
	bb.LeaveComponent(toleranceMark_globalrannodeid)
	toleranceMark_selectedtai := bb.EnterComponent("SelectedTAI")
	if err := s18.BridgeFiveGSTAIMethodUnmarshalAPERFrom(&v.SelectedTAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.SourceNgRanNodeIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SourceNgRanNodeIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERServedGUMMEIsListValue struct{ Value ServedGUMMEIs }

// MarshalAPERServedGUMMEIsTo appends a ServedGUMMEIs list to bb.
func BridgeMarshalAPERServedGUMMEIsTo(list ServedGUMMEIs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERServedGUMMEIsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ServedGUMMEIsItem to APER format.
func (v *ServedGUMMEIsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ServedGUMMEIsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.ServedPLMNs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_servedplmns, fragmentLength_servedplmns int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_servedplmns < 0 || fragmentOffset_servedplmns > int64(len(v.ServedPLMNs)) || fragmentLength_servedplmns < 0 || fragmentLength_servedplmns > int64(len(v.ServedPLMNs[fragmentOffset_servedplmns:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ServedPLMNs[fragmentOffset_servedplmns : fragmentOffset_servedplmns+fragmentLength_servedplmns] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding servedPLMNs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding servedPLMNs: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ServedGroupIDs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_servedgroupids, fragmentLength_servedgroupids int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_servedgroupids < 0 || fragmentOffset_servedgroupids > int64(len(v.ServedGroupIDs)) || fragmentLength_servedgroupids < 0 || fragmentLength_servedgroupids > int64(len(v.ServedGroupIDs[fragmentOffset_servedgroupids:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ServedGroupIDs[fragmentOffset_servedgroupids : fragmentOffset_servedgroupids+fragmentLength_servedgroupids] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding servedGroupIDs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding servedGroupIDs: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ServedMMECs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_servedmmecs, fragmentLength_servedmmecs int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_servedmmecs < 0 || fragmentOffset_servedmmecs > int64(len(v.ServedMMECs)) || fragmentLength_servedmmecs < 0 || fragmentLength_servedmmecs > int64(len(v.ServedMMECs[fragmentOffset_servedmmecs:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ServedMMECs[fragmentOffset_servedmmecs : fragmentOffset_servedmmecs+fragmentLength_servedmmecs] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 1, 1, true); err != nil {
				return fmt.Errorf("encoding servedMMECs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding servedMMECs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeServedGUMMEIsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ServedGUMMEIsItem from APER format.
func (v *ServedGUMMEIsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ServedGUMMEIsItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ServedGUMMEIsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ServedGUMMEIsItem")
	}
	bb.EnterComponent("ServedGUMMEIsItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ServedGUMMEIsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ServedGUMMEIsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedGUMMEIsItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ServedGUMMEIsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ServedGUMMEIsItem{}
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
	toleranceMark_servedplmns := bb.EnterComponent("ServedPLMNs")
	v.ServedPLMNs = make(s00.ServedPLMNs, 0)
	_, errCollection_servedplmns := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_servedplmns, fragmentLength_servedplmns int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_servedplmns < 0 || fragmentLength_servedplmns < 0 || fragmentLength_servedplmns > int64(^uint(0)>>1) || fragmentOffset_servedplmns > int64(^uint(0)>>1)-fragmentLength_servedplmns {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_servedplmns; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ServedPLMNs[%d]", fragmentOffset_servedplmns+i))
			}
			if next, err := aper.AppendValues(bb, v.ServedPLMNs, val); err != nil {
				return err
			} else {
				v.ServedPLMNs = next
			}
		}
		return nil
	})
	if errCollection_servedplmns != nil {
		return runtime.WrapDecodePath(errCollection_servedplmns, "ServedPLMNs")
	}
	bb.LeaveComponent(toleranceMark_servedplmns)
	toleranceMark_servedgroupids := bb.EnterComponent("ServedGroupIDs")
	v.ServedGroupIDs = make(s00.ServedGroupIDs, 0)
	_, errCollection_servedgroupids := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_servedgroupids, fragmentLength_servedgroupids int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_servedgroupids < 0 || fragmentLength_servedgroupids < 0 || fragmentLength_servedgroupids > int64(^uint(0)>>1) || fragmentOffset_servedgroupids > int64(^uint(0)>>1)-fragmentLength_servedgroupids {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_servedgroupids; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ServedGroupIDs[%d]", fragmentOffset_servedgroupids+i))
			}
			if next, err := aper.AppendValues(bb, v.ServedGroupIDs, val); err != nil {
				return err
			} else {
				v.ServedGroupIDs = next
			}
		}
		return nil
	})
	if errCollection_servedgroupids != nil {
		return runtime.WrapDecodePath(errCollection_servedgroupids, "ServedGroupIDs")
	}
	bb.LeaveComponent(toleranceMark_servedgroupids)
	toleranceMark_servedmmecs := bb.EnterComponent("ServedMMECs")
	v.ServedMMECs = make(s00.ServedMMECs, 0)
	_, errCollection_servedmmecs := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_servedmmecs, fragmentLength_servedmmecs int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_servedmmecs < 0 || fragmentLength_servedmmecs < 0 || fragmentLength_servedmmecs > int64(^uint(0)>>1) || fragmentOffset_servedmmecs > int64(^uint(0)>>1)-fragmentLength_servedmmecs {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_servedmmecs; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ServedMMECs[%d]", fragmentOffset_servedmmecs+i))
			}
			if next, err := aper.AppendValues(bb, v.ServedMMECs, val); err != nil {
				return err
			} else {
				v.ServedMMECs = next
			}
		}
		return nil
	})
	if errCollection_servedmmecs != nil {
		return runtime.WrapDecodePath(errCollection_servedmmecs, "ServedMMECs")
	}
	bb.LeaveComponent(toleranceMark_servedmmecs)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.ServedGUMMEIsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.ServedGUMMEIsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SubscriptionBasedUEDifferentiationInfo to APER format.
func (v *SubscriptionBasedUEDifferentiationInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SubscriptionBasedUEDifferentiationInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.PeriodicCommunicationIndicator != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.PeriodicTime != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ScheduledCommunicationTime != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.StationaryIndication != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.TrafficProfile != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.BatteryIndication != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.PeriodicCommunicationIndicator != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.PeriodicCommunicationIndicator), 2, true); err != nil {
			return fmt.Errorf("encoding periodicCommunicationIndicator: %w", err)
		}
	}
	if v.PeriodicTime != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PeriodicTime, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound10, true); err != nil {
			return fmt.Errorf("encoding periodicTime: %w", err)
		}
	}
	if v.ScheduledCommunicationTime != nil {
		if err := s28.BridgeScheduledCommunicationTimeMethodMarshalAPERTo(v.ScheduledCommunicationTime, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding scheduledCommunicationTime: %w", err)
		}
	}
	if v.StationaryIndication != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.StationaryIndication), 2, true); err != nil {
			return fmt.Errorf("encoding stationaryIndication: %w", err)
		}
	}
	if v.TrafficProfile != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.TrafficProfile), 3, true); err != nil {
			return fmt.Errorf("encoding trafficProfile: %w", err)
		}
	}
	if v.BatteryIndication != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.BatteryIndication), 3, true); err != nil {
			return fmt.Errorf("encoding batteryIndication: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SubscriptionBasedUEDifferentiationInfo from APER format.
func (v *SubscriptionBasedUEDifferentiationInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SubscriptionBasedUEDifferentiationInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SubscriptionBasedUEDifferentiationInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
	}
	bb.EnterComponent("SubscriptionBasedUEDifferentiationInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "SubscriptionBasedUEDifferentiationInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SubscriptionBasedUEDifferentiationInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SubscriptionBasedUEDifferentiationInfo{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_periodiccommunicationindicator, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_periodictime, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scheduledcommunicationtime, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_stationaryindication, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_trafficprofile, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_batteryindication, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_periodiccommunicationindicator {
		val_periodiccommunicationindicator, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PeriodicCommunicationIndicator"})
		if err != nil {
			return runtime.WrapDecodePath(err, "PeriodicCommunicationIndicator")
		}
		if err := aper.ChargeValue(bb, val_periodiccommunicationindicator); err != nil {
			return err
		}
		v.PeriodicCommunicationIndicator = (*int64)(bb.OwnInt64(int64(val_periodiccommunicationindicator)))

	}
	if opt_periodictime {
		val_periodictime, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound10, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PeriodicTime")
		}
		v.PeriodicTime = val_periodictime
	}
	if opt_scheduledcommunicationtime {
		toleranceMark_scheduledcommunicationtime := bb.EnterComponent("ScheduledCommunicationTime")
		var dec_scheduledcommunicationtime s28.ScheduledCommunicationTime
		if err := s28.BridgeScheduledCommunicationTimeMethodUnmarshalAPERFrom(&dec_scheduledcommunicationtime, bb); err != nil {
			return runtime.WrapDecodePath(err, "ScheduledCommunicationTime")
		}
		if err := aper.ChargeValue(bb, dec_scheduledcommunicationtime); err != nil {
			return err
		}
		v.ScheduledCommunicationTime = &dec_scheduledcommunicationtime
		bb.LeaveComponent(toleranceMark_scheduledcommunicationtime)
	}
	if opt_stationaryindication {
		val_stationaryindication, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "StationaryIndication"})
		if err != nil {
			return runtime.WrapDecodePath(err, "StationaryIndication")
		}
		if err := aper.ChargeValue(bb, val_stationaryindication); err != nil {
			return err
		}
		v.StationaryIndication = (*int64)(bb.OwnInt64(int64(val_stationaryindication)))

	}
	if opt_trafficprofile {
		val_trafficprofile, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TrafficProfile"})
		if err != nil {
			return runtime.WrapDecodePath(err, "TrafficProfile")
		}
		if err := aper.ChargeValue(bb, val_trafficprofile); err != nil {
			return err
		}
		v.TrafficProfile = (*int64)(bb.OwnInt64(int64(val_trafficprofile)))

	}
	if opt_batteryindication {
		val_batteryindication, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BatteryIndication"})
		if err != nil {
			return runtime.WrapDecodePath(err, "BatteryIndication")
		}
		if err := aper.ChargeValue(bb, val_batteryindication); err != nil {
			return err
		}
		v.BatteryIndication = (*int64)(bb.OwnInt64(int64(val_batteryindication)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERSupportedTAsListValue struct{ Value SupportedTAs }

// MarshalAPERSupportedTAsTo appends a SupportedTAs list to bb.
func BridgeMarshalAPERSupportedTAsTo(list SupportedTAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERSupportedTAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes SupportedTAsItem to APER format.
func (v *SupportedTAsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SupportedTAsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.TAC), 2, 2, true); err != nil {
		return fmt.Errorf("encoding tAC: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.BroadcastPLMNs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 6, HasUpper: true}, true, func(fragmentOffset_broadcastplmns, fragmentLength_broadcastplmns int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_broadcastplmns < 0 || fragmentOffset_broadcastplmns > int64(len(v.BroadcastPLMNs)) || fragmentLength_broadcastplmns < 0 || fragmentLength_broadcastplmns > int64(len(v.BroadcastPLMNs[fragmentOffset_broadcastplmns:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BroadcastPLMNs[fragmentOffset_broadcastplmns : fragmentOffset_broadcastplmns+fragmentLength_broadcastplmns] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding broadcastPLMNs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding broadcastPLMNs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SupportedTAsItem from APER format.
func (v *SupportedTAsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SupportedTAsItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SupportedTAsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAsItem")
	}
	bb.EnterComponent("SupportedTAsItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "SupportedTAsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAsItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SupportedTAsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SupportedTAsItem{}
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
	val_tac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAC")
	}
	v.TAC = s00.TAC(val_tac)
	toleranceMark_broadcastplmns := bb.EnterComponent("BroadcastPLMNs")
	v.BroadcastPLMNs = make(s00.BPLMNs, 0)
	_, errCollection_broadcastplmns := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 6, HasUpper: true}, true, func(fragmentOffset_broadcastplmns, fragmentLength_broadcastplmns int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_broadcastplmns < 0 || fragmentLength_broadcastplmns < 0 || fragmentLength_broadcastplmns > int64(^uint(0)>>1) || fragmentOffset_broadcastplmns > int64(^uint(0)>>1)-fragmentLength_broadcastplmns {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_broadcastplmns; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("BroadcastPLMNs[%d]", fragmentOffset_broadcastplmns+i))
			}
			if next, err := aper.AppendValues(bb, v.BroadcastPLMNs, val); err != nil {
				return err
			} else {
				v.BroadcastPLMNs = next
			}
		}
		return nil
	})
	if errCollection_broadcastplmns != nil {
		return runtime.WrapDecodePath(errCollection_broadcastplmns, "BroadcastPLMNs")
	}
	bb.LeaveComponent(toleranceMark_broadcastplmns)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.SupportedTAsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SupportedTAsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ConnectedengNBItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ConnectedengNBItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ConnectedengNBItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ConnectedengNBItem) WithoutReplay() ConnectedengNBItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ConnectedengNBItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SensorMeasConfigNameItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SensorMeasConfigNameItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SensorMeasConfigNameItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SensorMeasConfigNameItem) WithoutReplay() SensorMeasConfigNameItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SensorMeasConfigNameItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SensorMeasurementConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SensorMeasurementConfiguration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SensorMeasurementConfiguration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SensorMeasurementConfiguration) WithoutReplay() SensorMeasurementConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SensorMeasurementConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ServedDCNsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedDCNsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ServedDCNsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ServedDCNsItem) WithoutReplay() ServedDCNsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ServedDCNsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ServedGUMMEIsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedGUMMEIsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ServedGUMMEIsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ServedGUMMEIsItem) WithoutReplay() ServedGUMMEIsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ServedGUMMEIsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SourceNgRanNodeID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SourceNgRanNodeID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SourceNgRanNodeID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SourceNgRanNodeID) WithoutReplay() SourceNgRanNodeID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SourceNgRanNodeID
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SourceNodeID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SourceNodeID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SourceNodeID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SourceNodeID) WithoutReplay() SourceNodeID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SourceNodeID
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SubscriptionBasedUEDifferentiationInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SubscriptionBasedUEDifferentiationInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SubscriptionBasedUEDifferentiationInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SubscriptionBasedUEDifferentiationInfo) WithoutReplay() SubscriptionBasedUEDifferentiationInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SubscriptionBasedUEDifferentiationInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SupportedTAsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SupportedTAsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SupportedTAsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SupportedTAsItem) WithoutReplay() SupportedTAsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SupportedTAsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SynchronisationInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SynchronisationInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SynchronisationInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SynchronisationInformation) WithoutReplay() SynchronisationInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SynchronisationInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ConnectedengNBItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ConnectedengNBItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ConnectedengNBItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ConnectedengNBItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ConnectedengNBItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ConnectedengNBItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ConnectedengNBItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SensorMeasConfigNameItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SensorMeasConfigNameItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SensorMeasConfigNameItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SensorMeasConfigNameItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SensorMeasConfigNameItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SensorMeasConfigNameItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SensorMeasConfigNameItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SensorMeasurementConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SensorMeasurementConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SensorMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SensorMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SensorMeasurementConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SensorMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SensorMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ServedDCNsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ServedDCNsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ServedDCNsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ServedDCNsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ServedDCNsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ServedDCNsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ServedDCNsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ServedGUMMEIsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ServedGUMMEIsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ServedGUMMEIsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ServedGUMMEIsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ServedGUMMEIsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ServedGUMMEIsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ServedGUMMEIsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SourceNgRanNodeID) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SourceNgRanNodeID) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SourceNgRanNodeID.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SourceNgRanNodeID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SourceNgRanNodeID) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SourceNgRanNodeID.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SourceNgRanNodeID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SubscriptionBasedUEDifferentiationInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SubscriptionBasedUEDifferentiationInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SubscriptionBasedUEDifferentiationInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SubscriptionBasedUEDifferentiationInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SubscriptionBasedUEDifferentiationInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SubscriptionBasedUEDifferentiationInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SubscriptionBasedUEDifferentiationInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SupportedTAsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SupportedTAsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SupportedTAsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SupportedTAsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SupportedTAsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SupportedTAsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SupportedTAsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SynchronisationInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SynchronisationInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SynchronisationInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SynchronisationInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SynchronisationInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SynchronisationInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SynchronisationInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ConnectedengNBItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ConnectedengNBItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ConnectedengNBItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ConnectedengNBItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APConnectedengNBItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ConnectedengNBItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ConnectedengNBItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ConnectedengNBItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ConnectedengNBItem")
}
func (v *ConnectedengNBItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ConnectedengNBItem")
}
func (v *ConnectedengNBItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APConnectedengNBItem(v, &s)
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
func (v *ConnectedengNBItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ConnectedengNBItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SensorMeasConfigNameItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SensorMeasConfigNameItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SensorMeasConfigNameItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SensorMeasConfigNameItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSensorMeasConfigNameItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SensorMeasConfigNameItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SensorMeasConfigNameItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SensorMeasConfigNameItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SensorMeasConfigNameItem")
}
func (v *SensorMeasConfigNameItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SensorMeasConfigNameItem")
}
func (v *SensorMeasConfigNameItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSensorMeasConfigNameItem(v, &s)
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
func (v *SensorMeasConfigNameItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SensorMeasConfigNameItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SensorMeasurementConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SensorMeasurementConfiguration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SensorMeasurementConfiguration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SensorMeasurementConfiguration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSensorMeasurementConfiguration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SensorMeasurementConfiguration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SensorMeasurementConfiguration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SensorMeasurementConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SensorMeasurementConfiguration")
}
func (v *SensorMeasurementConfiguration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SensorMeasurementConfiguration")
}
func (v *SensorMeasurementConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSensorMeasurementConfiguration(v, &s)
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
func (v *SensorMeasurementConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SensorMeasurementConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ServedDCNsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ServedDCNsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ServedDCNsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ServedDCNsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APServedDCNsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ServedDCNsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ServedDCNsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ServedDCNsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ServedDCNsItem")
}
func (v *ServedDCNsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ServedDCNsItem")
}
func (v *ServedDCNsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APServedDCNsItem(v, &s)
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
func (v *ServedDCNsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ServedDCNsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ServedGUMMEIsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ServedGUMMEIsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ServedGUMMEIsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ServedGUMMEIsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APServedGUMMEIsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ServedGUMMEIsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ServedGUMMEIsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ServedGUMMEIsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ServedGUMMEIsItem")
}
func (v *ServedGUMMEIsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ServedGUMMEIsItem")
}
func (v *ServedGUMMEIsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APServedGUMMEIsItem(v, &s)
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
func (v *ServedGUMMEIsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ServedGUMMEIsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SourceNgRanNodeID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SourceNgRanNodeID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SourceNgRanNodeID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SourceNgRanNodeID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSourceNgRanNodeID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SourceNgRanNodeID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SourceNgRanNodeID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SourceNgRanNodeID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SourceNgRanNodeID")
}
func (v *SourceNgRanNodeID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SourceNgRanNodeID")
}
func (v *SourceNgRanNodeID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSourceNgRanNodeID(v, &s)
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
func (v *SourceNgRanNodeID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SourceNgRanNodeID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SourceNodeID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SourceNodeID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SourceNodeID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SourceNodeID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSourceNodeID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SourceNodeID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SourceNodeID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SourceNodeID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SourceNodeID")
}
func (v *SourceNodeID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SourceNodeID")
}
func (v *SourceNodeID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSourceNodeID(v, &s)
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
func (v *SourceNodeID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SourceNodeID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SubscriptionBasedUEDifferentiationInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SubscriptionBasedUEDifferentiationInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SubscriptionBasedUEDifferentiationInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SubscriptionBasedUEDifferentiationInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SubscriptionBasedUEDifferentiationInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SubscriptionBasedUEDifferentiationInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SubscriptionBasedUEDifferentiationInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SubscriptionBasedUEDifferentiationInfo")
}
func (v *SubscriptionBasedUEDifferentiationInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SubscriptionBasedUEDifferentiationInfo")
}
func (v *SubscriptionBasedUEDifferentiationInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v, &s)
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
func (v *SubscriptionBasedUEDifferentiationInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SubscriptionBasedUEDifferentiationInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SupportedTAsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SupportedTAsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SupportedTAsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SupportedTAsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSupportedTAsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SupportedTAsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SupportedTAsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SupportedTAsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SupportedTAsItem")
}
func (v *SupportedTAsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SupportedTAsItem")
}
func (v *SupportedTAsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSupportedTAsItem(v, &s)
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
func (v *SupportedTAsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SupportedTAsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SynchronisationInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SynchronisationInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SynchronisationInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SynchronisationInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSynchronisationInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SynchronisationInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SynchronisationInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SynchronisationInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SynchronisationInformation")
}
func (v *SynchronisationInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SynchronisationInformation")
}
func (v *SynchronisationInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSynchronisationInformation(v, &s)
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
func (v *SynchronisationInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SynchronisationInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ConnectedengNBItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ConnectedengNBItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ConnectedengNBItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APConnectedengNBItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ConnectedengNBItem{}
		return report, aper.OperationError(err, "ConnectedengNBItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ConnectedengNBItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SensorMeasConfigNameItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SensorMeasConfigNameItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SensorMeasConfigNameItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSensorMeasConfigNameItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SensorMeasConfigNameItem{}
		return report, aper.OperationError(err, "SensorMeasConfigNameItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SensorMeasConfigNameItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SensorMeasurementConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SensorMeasurementConfiguration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SensorMeasurementConfiguration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSensorMeasurementConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SensorMeasurementConfiguration{}
		return report, aper.OperationError(err, "SensorMeasurementConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SensorMeasurementConfiguration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ServedDCNsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ServedDCNsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ServedDCNsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APServedDCNsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ServedDCNsItem{}
		return report, aper.OperationError(err, "ServedDCNsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ServedDCNsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ServedGUMMEIsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ServedGUMMEIsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ServedGUMMEIsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APServedGUMMEIsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ServedGUMMEIsItem{}
		return report, aper.OperationError(err, "ServedGUMMEIsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ServedGUMMEIsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SourceNgRanNodeID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SourceNgRanNodeID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SourceNgRanNodeID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSourceNgRanNodeID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SourceNgRanNodeID{}
		return report, aper.OperationError(err, "SourceNgRanNodeID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SourceNgRanNodeID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SourceNodeID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SourceNodeID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SourceNodeID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSourceNodeID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SourceNodeID{}
		return report, aper.OperationError(err, "SourceNodeID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SourceNodeID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SubscriptionBasedUEDifferentiationInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SubscriptionBasedUEDifferentiationInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SubscriptionBasedUEDifferentiationInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SubscriptionBasedUEDifferentiationInfo{}
		return report, aper.OperationError(err, "SubscriptionBasedUEDifferentiationInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SubscriptionBasedUEDifferentiationInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SupportedTAsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SupportedTAsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SupportedTAsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSupportedTAsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SupportedTAsItem{}
		return report, aper.OperationError(err, "SupportedTAsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SupportedTAsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SynchronisationInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SynchronisationInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SynchronisationInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSynchronisationInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SynchronisationInformation{}
		return report, aper.OperationError(err, "SynchronisationInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SynchronisationInformation")
}

// NewSensorNameConfigUncompensatedBarometricConfig constructs a checked complete value.
func NewSensorNameConfigUncompensatedBarometricConfig(v int64, options ...aper.BuildOption) (s30.SensorNameConfig, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigUncompensatedBarometricConfig")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s30.SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigUncompensatedBarometricConfig")
	}
	value := BridgeNewSensorNameConfigUncompensatedBarometricConfigLegacy(v)
	if _, err := s30.BridgeSensorNameConfigMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s30.SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigUncompensatedBarometricConfig")
	}
	return value, aper.OperationError(nil, "SensorNameConfigUncompensatedBarometricConfig")
}

// NewSensorNameConfigChoiceExtensions constructs a checked complete value.
func NewSensorNameConfigChoiceExtensions(v s11.SensorNameConfigExtIEValueProtocolIESingleContainer, options ...aper.BuildOption) (s30.SensorNameConfig, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigChoiceExtensions")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s30.SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigChoiceExtensions")
	}
	value := BridgeNewSensorNameConfigChoiceExtensionsLegacy(v)
	if _, err := s30.BridgeSensorNameConfigMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s30.SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigChoiceExtensions")
	}
	return value, aper.OperationError(nil, "SensorNameConfigChoiceExtensions")
}

// NewSourceNodeIDSourceNgRanNodeID constructs a checked complete value.
func NewSourceNodeIDSourceNgRanNodeID(v SourceNgRanNodeID, options ...aper.BuildOption) (SourceNodeID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SourceNodeID{}, aper.OperationError(err, "SourceNodeIDSourceNgRanNodeID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return SourceNodeID{}, aper.OperationError(err, "SourceNodeIDSourceNgRanNodeID")
	}
	value := BridgeNewSourceNodeIDSourceNgRanNodeIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return SourceNodeID{}, aper.OperationError(err, "SourceNodeIDSourceNgRanNodeID")
	}
	return value, aper.OperationError(nil, "SourceNodeIDSourceNgRanNodeID")
}

// NewSourceNodeIDSourceNodeIDExtension constructs a checked complete value.
func NewSourceNodeIDSourceNodeIDExtension(v s20.SourceNodeIDExtension, options ...aper.BuildOption) (SourceNodeID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SourceNodeID{}, aper.OperationError(err, "SourceNodeIDSourceNodeIDExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return SourceNodeID{}, aper.OperationError(err, "SourceNodeIDSourceNodeIDExtension")
	}
	value := BridgeNewSourceNodeIDSourceNodeIDExtensionLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return SourceNodeID{}, aper.OperationError(err, "SourceNodeIDSourceNodeIDExtension")
	}
	return value, aper.OperationError(nil, "SourceNodeIDSourceNodeIDExtension")
}

// ConnectionEstablishmentIndication represents the ASN.1 type ConnectionEstablishmentIndication (SEQUENCE).
type ConnectionEstablishmentIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ConnectionEstablishmentIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ConnectionEstablishmentIndication to APER format.
func (v *ConnectionEstablishmentIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ConnectionEstablishmentIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ConnectionEstablishmentIndication from APER format.
func (v *ConnectionEstablishmentIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ConnectionEstablishmentIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ConnectionEstablishmentIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ConnectionEstablishmentIndication")
	}
	bb.EnterComponent("ConnectionEstablishmentIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ConnectionEstablishmentIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ConnectionEstablishmentIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ConnectionEstablishmentIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ConnectionEstablishmentIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ConnectionEstablishmentIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ConnectionEstablishmentIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ConnectionEstablishmentIndicationIEField
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
func (v *ConnectionEstablishmentIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ConnectionEstablishmentIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ConnectionEstablishmentIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ConnectionEstablishmentIndication) WithoutReplay() ConnectionEstablishmentIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ConnectionEstablishmentIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ConnectionEstablishmentIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ConnectionEstablishmentIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ConnectionEstablishmentIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ConnectionEstablishmentIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ConnectionEstablishmentIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ConnectionEstablishmentIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ConnectionEstablishmentIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ConnectionEstablishmentIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ConnectionEstablishmentIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ConnectionEstablishmentIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APConnectionEstablishmentIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ConnectionEstablishmentIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ConnectionEstablishmentIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ConnectionEstablishmentIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ConnectionEstablishmentIndication")
}
func (v *ConnectionEstablishmentIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ConnectionEstablishmentIndication")
}
func (v *ConnectionEstablishmentIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APConnectionEstablishmentIndication(v, &s)
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
func (v *ConnectionEstablishmentIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ConnectionEstablishmentIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ConnectionEstablishmentIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ConnectionEstablishmentIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ConnectionEstablishmentIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APConnectionEstablishmentIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ConnectionEstablishmentIndication{}
		return report, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ConnectionEstablishmentIndication")
}

type ConnectionEstablishmentIndicationIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowMMEUES1APID                            *s00.MMEUES1APID
	rowENBUES1APID                            *s00.ENBUES1APID
	rowUERadioCapability                      *s00.UERadioCapability
	rowEnhancedCoverageRestricted             *s00.EnhancedCoverageRestricted
	rowDLCPSecurityInformation                *s15.DLCPSecurityInformation
	rowCEModeBRestricted                      *s00.CEModeBRestricted
	rowEndIndication                          *s00.EndIndication
	rowSubscriptionBasedUEDifferentiationInfo *SubscriptionBasedUEDifferentiationInfo
	rowUELevelQoSParameters                   *s18.ERABLevelQoSParameters
	rowUERadioCapabilityID                    *s00.UERadioCapabilityID
	rowMaskedIMEISV                           *s00.MaskedIMEISV
	rowCoarseUELocation                       *s00.CoarseUELocation
}

func (v ConnectionEstablishmentIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(74):
		return v.rowUERadioCapability != nil
	case s00.ProtocolIEID(251):
		return v.rowEnhancedCoverageRestricted != nil
	case s00.ProtocolIEID(253):
		return v.rowDLCPSecurityInformation != nil
	case s00.ProtocolIEID(271):
		return v.rowCEModeBRestricted != nil
	case s00.ProtocolIEID(280):
		return v.rowEndIndication != nil
	case s00.ProtocolIEID(278):
		return v.rowSubscriptionBasedUEDifferentiationInfo != nil
	case s00.ProtocolIEID(252):
		return v.rowUELevelQoSParameters != nil
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(192):
		return v.rowMaskedIMEISV != nil
	case s00.ProtocolIEID(354):
		return v.rowCoarseUELocation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ConnectionEstablishmentIndicationIEValue and reports whether the opaque alternative is selected.
func (v *ConnectionEstablishmentIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ConnectionEstablishmentIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs"}}
}
func (ConnectionEstablishmentIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(74):
		return aper.UnknownSelector
	case s00.ProtocolIEID(251):
		return aper.UnknownSelector
	case s00.ProtocolIEID(253):
		return aper.UnknownSelector
	case s00.ProtocolIEID(271):
		return aper.UnknownSelector
	case s00.ProtocolIEID(280):
		return aper.UnknownSelector
	case s00.ProtocolIEID(278):
		return aper.UnknownSelector
	case s00.ProtocolIEID(252):
		return aper.UnknownSelector
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(192):
		return aper.UnknownSelector
	case s00.ProtocolIEID(354):
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
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsMMEUES1APID returns the selected MMEUES1APID value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsUERadioCapability returns the selected UERadioCapability value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsUERadioCapability() (*s00.UERadioCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(74) || v.rowUERadioCapability == nil {
		return nil, false
	}
	return v.rowUERadioCapability, true
}

// AsEnhancedCoverageRestricted returns the selected EnhancedCoverageRestricted value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsEnhancedCoverageRestricted() (*s00.EnhancedCoverageRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(251) || v.rowEnhancedCoverageRestricted == nil {
		return nil, false
	}
	return v.rowEnhancedCoverageRestricted, true
}

// AsDLCPSecurityInformation returns the selected DLCPSecurityInformation value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsDLCPSecurityInformation() (*s15.DLCPSecurityInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(253) || v.rowDLCPSecurityInformation == nil {
		return nil, false
	}
	return v.rowDLCPSecurityInformation, true
}

// AsCEModeBRestricted returns the selected CEModeBRestricted value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsCEModeBRestricted() (*s00.CEModeBRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(271) || v.rowCEModeBRestricted == nil {
		return nil, false
	}
	return v.rowCEModeBRestricted, true
}

// AsEndIndication returns the selected EndIndication value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsEndIndication() (*s00.EndIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(280) || v.rowEndIndication == nil {
		return nil, false
	}
	return v.rowEndIndication, true
}

// AsSubscriptionBasedUEDifferentiationInfo returns the selected SubscriptionBasedUEDifferentiationInfo value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsSubscriptionBasedUEDifferentiationInfo() (*SubscriptionBasedUEDifferentiationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(278) || v.rowSubscriptionBasedUEDifferentiationInfo == nil {
		return nil, false
	}
	return v.rowSubscriptionBasedUEDifferentiationInfo, true
}

// AsUELevelQoSParameters returns the selected UELevelQoSParameters value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsUELevelQoSParameters() (*s18.ERABLevelQoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(252) || v.rowUELevelQoSParameters == nil {
		return nil, false
	}
	return v.rowUELevelQoSParameters, true
}

// AsUERadioCapabilityID returns the selected UERadioCapabilityID value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}

// AsMaskedIMEISV returns the selected MaskedIMEISV value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsMaskedIMEISV() (*s00.MaskedIMEISV, bool) {
	if v == nil || v.id != s00.ProtocolIEID(192) || v.rowMaskedIMEISV == nil {
		return nil, false
	}
	return v.rowMaskedIMEISV, true
}

// AsCoarseUELocation returns the selected CoarseUELocation value of ConnectionEstablishmentIndicationIEValue and reports whether that alternative is active.
func (v *ConnectionEstablishmentIndicationIEValue) AsCoarseUELocation() (*s00.CoarseUELocation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(354) || v.rowCoarseUELocation == nil {
		return nil, false
	}
	return v.rowCoarseUELocation, true
}
func (v ConnectionEstablishmentIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ConnectionEstablishmentIndicationIEValue, error) {
	out := ConnectionEstablishmentIndicationIEValue{id: id}
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
	case s00.ProtocolIEID(74):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapability, error) {
			var v struct{ Value s00.UERadioCapability }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapability(val_value)
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
		out.rowUERadioCapability = &value
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
	case s00.ProtocolIEID(253):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s15.DLCPSecurityInformation
		child := scope
		if err := s15.BridgeDLCPSecurityInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "DLCPSecurityInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DLCPSecurityInformation")
		if err != nil {
			return out, err
		}
		*s15.BridgeDLCPSecurityInformationFieldPerPadding(&value) = padding
		*s15.BridgeDLCPSecurityInformationFieldReceived(&value) = true
		raw.RetainContents(s15.BridgeDLCPSecurityInformationFieldReceivedBytes(&value))
		*s15.BridgeDLCPSecurityInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowDLCPSecurityInformation = &value
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
	case s00.ProtocolIEID(280):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EndIndication"})
		value := s00.EndIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EndIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEndIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(278):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SubscriptionBasedUEDifferentiationInfo
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SubscriptionBasedUEDifferentiationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SubscriptionBasedUEDifferentiationInfo")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSubscriptionBasedUEDifferentiationInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(252):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.ERABLevelQoSParameters
		child := scope
		if err := s18.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UELevelQoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABLevelQoSParameters")
		if err != nil {
			return out, err
		}
		*s18.BridgeERABLevelQoSParametersFieldPerPadding(&value) = padding
		*s18.BridgeERABLevelQoSParametersFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeERABLevelQoSParametersFieldReceivedBytes(&value))
		*s18.BridgeERABLevelQoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUELevelQoSParameters = &value
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
	case s00.ProtocolIEID(354):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CoarseUELocation, error) {
			var v struct{ Value s00.CoarseUELocation }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CoarseUELocation(val_value)
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
		out.rowCoarseUELocation = &value
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
func (v ConnectionEstablishmentIndicationIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ConnectionEstablishmentIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(74):
		if v.rowUERadioCapability == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-UERadioCapability:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapability, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapability }{Value: value}
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
		})(*v.rowUERadioCapability, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(251):
		if v.rowEnhancedCoverageRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-EnhancedCoverageRestricted:")
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
	case s00.ProtocolIEID(253):
		if v.rowDLCPSecurityInformation == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-DL-CP-SecurityInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s15.BridgeDLCPSecurityInformationMethodMarshalAPERBudget(v.rowDLCPSecurityInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(271):
		if v.rowCEModeBRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-CE-ModeBRestricted:")
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
	case s00.ProtocolIEID(280):
		if v.rowEndIndication == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-EndIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEndIndication), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(278):
		if v.rowSubscriptionBasedUEDifferentiationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-Subscription-Based-UE-DifferentiationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSubscriptionBasedUEDifferentiationInfo.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(252):
		if v.rowUELevelQoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-UE-Level-QoS-Parameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeERABLevelQoSParametersMethodMarshalAPERBudget(v.rowUELevelQoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-UERadioCapabilityID:")
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
	case s00.ProtocolIEID(192):
		if v.rowMaskedIMEISV == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-Masked-IMEISV:")
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
	case s00.ProtocolIEID(354):
		if v.rowCoarseUELocation == nil {
			return nil, fmt.Errorf("%s missing value", "ConnectionEstablishmentIndicationIEs.id-CoarseUELocation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CoarseUELocation, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CoarseUELocation }{Value: value}
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
		})(*v.rowCoarseUELocation, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ConnectionEstablishmentIndicationIEValue:", v.id)
	}
}

type UEInformationTransferIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowSTMSI                                  *s28.STMSI
	rowUELevelQoSParameters                   *s18.ERABLevelQoSParameters
	rowUERadioCapability                      *s00.UERadioCapability
	rowSubscriptionBasedUEDifferentiationInfo *SubscriptionBasedUEDifferentiationInfo
	rowPendingDataIndication                  *s00.PendingDataIndication
	rowMaskedIMEISV                           *s00.MaskedIMEISV
}

func (v UEInformationTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(96):
		return v.rowSTMSI != nil
	case s00.ProtocolIEID(252):
		return v.rowUELevelQoSParameters != nil
	case s00.ProtocolIEID(74):
		return v.rowUERadioCapability != nil
	case s00.ProtocolIEID(278):
		return v.rowSubscriptionBasedUEDifferentiationInfo != nil
	case s00.ProtocolIEID(283):
		return v.rowPendingDataIndication != nil
	case s00.ProtocolIEID(192):
		return v.rowMaskedIMEISV != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEInformationTransferIEValue and reports whether the opaque alternative is selected.
func (v *UEInformationTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEInformationTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs"}}
}
func (UEInformationTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(96):
		return aper.UnknownSelector
	case s00.ProtocolIEID(252):
		return aper.UnknownSelector
	case s00.ProtocolIEID(74):
		return aper.UnknownSelector
	case s00.ProtocolIEID(278):
		return aper.UnknownSelector
	case s00.ProtocolIEID(283):
		return aper.UnknownSelector
	case s00.ProtocolIEID(192):
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

// AsSTMSI returns the selected STMSI value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsSTMSI() (*s28.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}

// AsUELevelQoSParameters returns the selected UELevelQoSParameters value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsUELevelQoSParameters() (*s18.ERABLevelQoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(252) || v.rowUELevelQoSParameters == nil {
		return nil, false
	}
	return v.rowUELevelQoSParameters, true
}

// AsUERadioCapability returns the selected UERadioCapability value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsUERadioCapability() (*s00.UERadioCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(74) || v.rowUERadioCapability == nil {
		return nil, false
	}
	return v.rowUERadioCapability, true
}

// AsSubscriptionBasedUEDifferentiationInfo returns the selected SubscriptionBasedUEDifferentiationInfo value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsSubscriptionBasedUEDifferentiationInfo() (*SubscriptionBasedUEDifferentiationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(278) || v.rowSubscriptionBasedUEDifferentiationInfo == nil {
		return nil, false
	}
	return v.rowSubscriptionBasedUEDifferentiationInfo, true
}

// AsPendingDataIndication returns the selected PendingDataIndication value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsPendingDataIndication() (*s00.PendingDataIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(283) || v.rowPendingDataIndication == nil {
		return nil, false
	}
	return v.rowPendingDataIndication, true
}

// AsMaskedIMEISV returns the selected MaskedIMEISV value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsMaskedIMEISV() (*s00.MaskedIMEISV, bool) {
	if v == nil || v.id != s00.ProtocolIEID(192) || v.rowMaskedIMEISV == nil {
		return nil, false
	}
	return v.rowMaskedIMEISV, true
}
func (v UEInformationTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEInformationTransferIEValue, error) {
	out := UEInformationTransferIEValue{id: id}
	switch id {
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
	case s00.ProtocolIEID(252):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.ERABLevelQoSParameters
		child := scope
		if err := s18.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UELevelQoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABLevelQoSParameters")
		if err != nil {
			return out, err
		}
		*s18.BridgeERABLevelQoSParametersFieldPerPadding(&value) = padding
		*s18.BridgeERABLevelQoSParametersFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeERABLevelQoSParametersFieldReceivedBytes(&value))
		*s18.BridgeERABLevelQoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUELevelQoSParameters = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(74):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapability, error) {
			var v struct{ Value s00.UERadioCapability }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapability(val_value)
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
		out.rowUERadioCapability = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(278):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SubscriptionBasedUEDifferentiationInfo
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SubscriptionBasedUEDifferentiationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SubscriptionBasedUEDifferentiationInfo")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSubscriptionBasedUEDifferentiationInfo = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEInformationTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEInformationTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(96):
		if v.rowSTMSI == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-S-TMSI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(252):
		if v.rowUELevelQoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-UE-Level-QoS-Parameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeERABLevelQoSParametersMethodMarshalAPERBudget(v.rowUELevelQoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(74):
		if v.rowUERadioCapability == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-UERadioCapability:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapability, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapability }{Value: value}
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
		})(*v.rowUERadioCapability, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(278):
		if v.rowSubscriptionBasedUEDifferentiationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-Subscription-Based-UE-DifferentiationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSubscriptionBasedUEDifferentiationInfo.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(283):
		if v.rowPendingDataIndication == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-PendingDataIndication:")
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
	case s00.ProtocolIEID(192):
		if v.rowMaskedIMEISV == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-Masked-IMEISV:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEInformationTransferIEValue:", v.id)
	}
}

type ConnectionEstablishmentIndicationIETable struct{}

func ConnectionEstablishmentIndicationIEs() ConnectionEstablishmentIndicationIETable {
	return ConnectionEstablishmentIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of ConnectionEstablishmentIndicationIETable.
func (ConnectionEstablishmentIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ConnectionEstablishmentIndicationIETable.
func (ConnectionEstablishmentIndicationIETable) Table() s00.ConnectionEstablishmentIndicationIEValueIETable {
	return func() s00.ConnectionEstablishmentIndicationIEValueIETable {
		sealed := s00.ConnectionEstablishmentIndicationIEValueIETable{}
		*s00.BridgeConnectionEstablishmentIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ConnectionEstablishmentIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) MMEUES1APID() ConnectionEstablishmentIndicationMMEUES1APIDIEBinding {
	return ConnectionEstablishmentIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) ENBUES1APID() ConnectionEstablishmentIndicationENBUES1APIDIEBinding {
	return ConnectionEstablishmentIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoUERadioCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(74), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-UERadioCapability"}}}
}

// UERadioCapability returns the typed binding for the UERadioCapability row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) UERadioCapability() ConnectionEstablishmentIndicationUERadioCapabilityIEBinding {
	return ConnectionEstablishmentIndicationUERadioCapabilityIEBinding{info: t.infoUERadioCapability(), codec: func() s02.UERadioCapabilityValueCodec {
		sealed := s02.UERadioCapabilityValueCodec{}
		*s02.BridgeUERadioCapabilityValueCodecFieldPath(&sealed) = "UERadioCapability"
		*s02.BridgeUERadioCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapability")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(74), raw)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, runtime.WrapDecodePath(err, "UERadioCapability")
			}
			value, ok := decoded.AsUERadioCapability()
			if !ok {
				var empty s00.UERadioCapability
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-UERadioCapability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapability, options aper.DecodeState) (s00.UERadioCapability, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERadioCapability(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s02.BridgeUERadioCapabilityValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapability, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUERadioCapability(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapability"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERadioCapability) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.UERadioCapability, bool) {
			return value.AsUERadioCapability()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) EnhancedCoverageRestricted() ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding {
	return ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding{info: t.infoEnhancedCoverageRestricted(), codec: func() s00.EnhancedCoverageRestrictedValueCodec {
		sealed := s00.EnhancedCoverageRestrictedValueCodec{}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EnhancedCoverageRestricted")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(251), raw)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, runtime.WrapDecodePath(err, "EnhancedCoverageRestricted")
			}
			value, ok := decoded.AsEnhancedCoverageRestricted()
			if !ok {
				var empty s00.EnhancedCoverageRestricted
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-EnhancedCoverageRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.EnhancedCoverageRestricted) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoDLCPSecurityInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(253), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DL-CP-SecurityInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-DL-CP-SecurityInformation"}}}
}

// DLCPSecurityInformation returns the typed binding for the DLCPSecurityInformation row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) DLCPSecurityInformation() ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding {
	return ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding{info: t.infoDLCPSecurityInformation(), codec: func() s15.DLCPSecurityInformationValueCodec {
		sealed := s15.DLCPSecurityInformationValueCodec{}
		*s15.BridgeDLCPSecurityInformationValueCodecFieldPath(&sealed) = "DLCPSecurityInformation"
		*s15.BridgeDLCPSecurityInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.DLCPSecurityInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s15.DLCPSecurityInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DLCPSecurityInformation")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(253), raw)
			if err != nil {
				var empty s15.DLCPSecurityInformation
				return empty, runtime.WrapDecodePath(err, "DLCPSecurityInformation")
			}
			value, ok := decoded.AsDLCPSecurityInformation()
			if !ok {
				var empty s15.DLCPSecurityInformation
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-DL-CP-SecurityInformation: no selected value")
			}
			return *value, nil
		}
		*s15.BridgeDLCPSecurityInformationValueCodecFieldEncode(&sealed) = func(value s15.DLCPSecurityInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(253), rowDLCPSecurityInformation: &value}).encodeFresh(fresh, budget)
		}
		*s15.BridgeDLCPSecurityInformationValueCodecFieldCapture(&sealed) = func(v s15.DLCPSecurityInformation, options aper.DecodeState) (s15.DLCPSecurityInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeCaptureS1APDLCPSecurityInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s15.BridgeDLCPSecurityInformationValueCodecFieldCompare(&sealed) = func(v s15.DLCPSecurityInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s15.BridgeCompareS1APDLCPSecurityInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeDLCPSecurityInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLCPSecurityInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s15.DLCPSecurityInformation) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(253), rowDLCPSecurityInformation: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s15.DLCPSecurityInformation, bool) {
			return value.AsDLCPSecurityInformation()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) CEModeBRestricted() ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding {
	return ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding{info: t.infoCEModeBRestricted(), codec: func() s00.CEModeBRestrictedValueCodec {
		sealed := s00.CEModeBRestrictedValueCodec{}
		*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
		*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CEModeBRestricted")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(271), raw)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, runtime.WrapDecodePath(err, "CEModeBRestricted")
			}
			value, ok := decoded.AsCEModeBRestricted()
			if !ok {
				var empty s00.CEModeBRestricted
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-CE-ModeBRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.CEModeBRestricted) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.CEModeBRestricted, bool) {
			return value.AsCEModeBRestricted()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoEndIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(280), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EndIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-EndIndication"}}}
}

// EndIndication returns the typed binding for the EndIndication row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) EndIndication() ConnectionEstablishmentIndicationEndIndicationIEBinding {
	return ConnectionEstablishmentIndicationEndIndicationIEBinding{info: t.infoEndIndication(), codec: func() s00.EndIndicationValueCodec {
		sealed := s00.EndIndicationValueCodec{}
		*s00.BridgeEndIndicationValueCodecFieldPath(&sealed) = "EndIndication"
		*s00.BridgeEndIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EndIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EndIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EndIndication")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(280), raw)
			if err != nil {
				var empty s00.EndIndication
				return empty, runtime.WrapDecodePath(err, "EndIndication")
			}
			value, ok := decoded.AsEndIndication()
			if !ok {
				var empty s00.EndIndication
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-EndIndication: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEndIndicationValueCodecFieldEncode(&sealed) = func(value s00.EndIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(280), rowEndIndication: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEndIndicationValueCodecFieldCapture(&sealed) = func(v s00.EndIndication, options aper.DecodeState) (s00.EndIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEndIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEndIndicationValueCodecFieldCompare(&sealed) = func(v s00.EndIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEndIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeEndIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EndIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EndIndication) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(280), rowEndIndication: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.EndIndication, bool) {
			return value.AsEndIndication()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) SubscriptionBasedUEDifferentiationInfo() ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding {
	return ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding{info: t.infoSubscriptionBasedUEDifferentiationInfo(), codec: SubscriptionBasedUEDifferentiationInfoValueCodec{path: "SubscriptionBasedUEDifferentiationInfo",
		decode: func(data []byte, options aper.DecodeState) (SubscriptionBasedUEDifferentiationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SubscriptionBasedUEDifferentiationInfo")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(278), raw)
			if err != nil {
				var empty SubscriptionBasedUEDifferentiationInfo
				return empty, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
			}
			value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
			if !ok {
				var empty SubscriptionBasedUEDifferentiationInfo
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
			}
			return *value, nil
		},
		encode: func(value SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SubscriptionBasedUEDifferentiationInfo) ConnectionEstablishmentIndicationIEValue {
		return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}
	}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*SubscriptionBasedUEDifferentiationInfo, bool) {
		return value.AsSubscriptionBasedUEDifferentiationInfo()
	}}
}
func (ConnectionEstablishmentIndicationIETable) infoUELevelQoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(252), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABLevelQoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-UE-Level-QoS-Parameters"}}}
}

// UELevelQoSParameters returns the typed binding for the UELevelQoSParameters row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) UELevelQoSParameters() ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding {
	return ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding{info: t.infoUELevelQoSParameters(), codec: func() s18.ERABLevelQoSParametersValueCodec {
		sealed := s18.ERABLevelQoSParametersValueCodec{}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldPath(&sealed) = "ERABLevelQoSParameters"
		*s18.BridgeERABLevelQoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABLevelQoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.ERABLevelQoSParameters
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABLevelQoSParameters")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(252), raw)
			if err != nil {
				var empty s18.ERABLevelQoSParameters
				return empty, runtime.WrapDecodePath(err, "ERABLevelQoSParameters")
			}
			value, ok := decoded.AsUELevelQoSParameters()
			if !ok {
				var empty s18.ERABLevelQoSParameters
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-UE-Level-QoS-Parameters: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldEncode(&sealed) = func(value s18.ERABLevelQoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(252), rowUELevelQoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldCapture(&sealed) = func(v s18.ERABLevelQoSParameters, options aper.DecodeState) (s18.ERABLevelQoSParameters, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APERABLevelQoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldCompare(&sealed) = func(v s18.ERABLevelQoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APERABLevelQoSParameters(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABLevelQoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.ERABLevelQoSParameters) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(252), rowUELevelQoSParameters: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s18.ERABLevelQoSParameters, bool) {
			return value.AsUELevelQoSParameters()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) UERadioCapabilityID() ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding {
	return ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, runtime.WrapDecodePath(err, "UERadioCapabilityID")
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.UERadioCapabilityID) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoMaskedIMEISV() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(192), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Masked-IMEISV"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-Masked-IMEISV"}}}
}

// MaskedIMEISV returns the typed binding for the MaskedIMEISV row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) MaskedIMEISV() ConnectionEstablishmentIndicationMaskedIMEISVIEBinding {
	return ConnectionEstablishmentIndicationMaskedIMEISVIEBinding{info: t.infoMaskedIMEISV(), codec: func() s01.MaskedIMEISVValueCodec {
		sealed := s01.MaskedIMEISVValueCodec{}
		*s01.BridgeMaskedIMEISVValueCodecFieldPath(&sealed) = "MaskedIMEISV"
		*s01.BridgeMaskedIMEISVValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MaskedIMEISV, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MaskedIMEISV")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(192), raw)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, runtime.WrapDecodePath(err, "MaskedIMEISV")
			}
			value, ok := decoded.AsMaskedIMEISV()
			if !ok {
				var empty s00.MaskedIMEISV
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-Masked-IMEISV: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&sealed) = func(value s00.MaskedIMEISV, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldCapture(&sealed) = func(v s00.MaskedIMEISV, options aper.DecodeState) (s00.MaskedIMEISV, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMaskedIMEISV(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldCompare(&sealed) = func(v s00.MaskedIMEISV, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMaskedIMEISV(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MaskedIMEISV"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MaskedIMEISV) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.MaskedIMEISV, bool) {
			return value.AsMaskedIMEISV()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoCoarseUELocation() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(354), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CoarseUELocation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-CoarseUELocation"}}}
}

// CoarseUELocation returns the typed binding for the CoarseUELocation row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) CoarseUELocation() ConnectionEstablishmentIndicationCoarseUELocationIEBinding {
	return ConnectionEstablishmentIndicationCoarseUELocationIEBinding{info: t.infoCoarseUELocation(), codec: func() s00.CoarseUELocationValueCodec {
		sealed := s00.CoarseUELocationValueCodec{}
		*s00.BridgeCoarseUELocationValueCodecFieldPath(&sealed) = "CoarseUELocation"
		*s00.BridgeCoarseUELocationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CoarseUELocation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CoarseUELocation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CoarseUELocation")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(354), raw)
			if err != nil {
				var empty s00.CoarseUELocation
				return empty, runtime.WrapDecodePath(err, "CoarseUELocation")
			}
			value, ok := decoded.AsCoarseUELocation()
			if !ok {
				var empty s00.CoarseUELocation
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-CoarseUELocation: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCoarseUELocationValueCodecFieldEncode(&sealed) = func(value s00.CoarseUELocation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(354), rowCoarseUELocation: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCoarseUELocationValueCodecFieldCapture(&sealed) = func(v s00.CoarseUELocation, options aper.DecodeState) (s00.CoarseUELocation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCoarseUELocation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCoarseUELocationValueCodecFieldCompare(&sealed) = func(v s00.CoarseUELocation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCoarseUELocation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCoarseUELocationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CoarseUELocation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CoarseUELocation) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(354), rowCoarseUELocation: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s00.CoarseUELocation, bool) {
			return value.AsCoarseUELocation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ConnectionEstablishmentIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(74):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(253):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-DL-CP-SecurityInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(280):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-EndIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(252):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Level-QoS-Parameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(192):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Masked-IMEISV requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(354):
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CoarseUELocation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return ConnectionEstablishmentIndicationIEField{Id: id, Criticality: criticality, Value: ConnectionEstablishmentIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEInformationTransferIETable struct{}

func UEInformationTransferIEs() UEInformationTransferIETable { return UEInformationTransferIETable{} }

// ID returns the ASN.1 object-set identity of UEInformationTransferIETable.
func (UEInformationTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEInformationTransferIETable.
func (UEInformationTransferIETable) Table() s00.UEInformationTransferIEValueIETable {
	return func() s00.UEInformationTransferIEValueIETable {
		sealed := s00.UEInformationTransferIEValueIETable{}
		*s00.BridgeUEInformationTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEInformationTransferIETable) infoSTMSI() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(96), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-S-TMSI"}}}
}

// STMSI returns the typed binding for the STMSI row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) STMSI() UEInformationTransferSTMSIIEBinding {
	return UEInformationTransferSTMSIIEBinding{info: t.infoSTMSI(), codec: func() s28.STMSIValueCodec {
		sealed := s28.STMSIValueCodec{}
		*s28.BridgeSTMSIValueCodecFieldPath(&sealed) = "STMSI"
		*s28.BridgeSTMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.STMSI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.STMSI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("STMSI")
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(96), raw)
			if err != nil {
				var empty s28.STMSI
				return empty, runtime.WrapDecodePath(err, "STMSI")
			}
			value, ok := decoded.AsSTMSI()
			if !ok {
				var empty s28.STMSI
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-S-TMSI: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSTMSIValueCodecFieldEncode(&sealed) = func(value s28.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s28.STMSI) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s28.STMSI, bool) { return value.AsSTMSI() }}
}
func (UEInformationTransferIETable) infoUELevelQoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(252), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABLevelQoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-UE-Level-QoS-Parameters"}}}
}

// UELevelQoSParameters returns the typed binding for the UELevelQoSParameters row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) UELevelQoSParameters() UEInformationTransferERABLevelQoSParametersIEBinding {
	return UEInformationTransferERABLevelQoSParametersIEBinding{info: t.infoUELevelQoSParameters(), codec: func() s18.ERABLevelQoSParametersValueCodec {
		sealed := s18.ERABLevelQoSParametersValueCodec{}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldPath(&sealed) = "ERABLevelQoSParameters"
		*s18.BridgeERABLevelQoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABLevelQoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.ERABLevelQoSParameters
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABLevelQoSParameters")
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(252), raw)
			if err != nil {
				var empty s18.ERABLevelQoSParameters
				return empty, runtime.WrapDecodePath(err, "ERABLevelQoSParameters")
			}
			value, ok := decoded.AsUELevelQoSParameters()
			if !ok {
				var empty s18.ERABLevelQoSParameters
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-UE-Level-QoS-Parameters: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldEncode(&sealed) = func(value s18.ERABLevelQoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(252), rowUELevelQoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldCapture(&sealed) = func(v s18.ERABLevelQoSParameters, options aper.DecodeState) (s18.ERABLevelQoSParameters, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APERABLevelQoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldCompare(&sealed) = func(v s18.ERABLevelQoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APERABLevelQoSParameters(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABLevelQoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.ERABLevelQoSParameters) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(252), rowUELevelQoSParameters: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s18.ERABLevelQoSParameters, bool) {
			return value.AsUELevelQoSParameters()
		}}
}
func (UEInformationTransferIETable) infoUERadioCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(74), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-UERadioCapability"}}}
}

// UERadioCapability returns the typed binding for the UERadioCapability row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) UERadioCapability() UEInformationTransferUERadioCapabilityIEBinding {
	return UEInformationTransferUERadioCapabilityIEBinding{info: t.infoUERadioCapability(), codec: func() s02.UERadioCapabilityValueCodec {
		sealed := s02.UERadioCapabilityValueCodec{}
		*s02.BridgeUERadioCapabilityValueCodecFieldPath(&sealed) = "UERadioCapability"
		*s02.BridgeUERadioCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapability")
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(74), raw)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, runtime.WrapDecodePath(err, "UERadioCapability")
			}
			value, ok := decoded.AsUERadioCapability()
			if !ok {
				var empty s00.UERadioCapability
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-UERadioCapability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapability, options aper.DecodeState) (s00.UERadioCapability, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERadioCapability(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s02.BridgeUERadioCapabilityValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapability, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUERadioCapability(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapability"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERadioCapability) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s00.UERadioCapability, bool) {
			return value.AsUERadioCapability()
		}}
}
func (UEInformationTransferIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) SubscriptionBasedUEDifferentiationInfo() UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding {
	return UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding{info: t.infoSubscriptionBasedUEDifferentiationInfo(), codec: SubscriptionBasedUEDifferentiationInfoValueCodec{path: "SubscriptionBasedUEDifferentiationInfo",
		decode: func(data []byte, options aper.DecodeState) (SubscriptionBasedUEDifferentiationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SubscriptionBasedUEDifferentiationInfo")
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(278), raw)
			if err != nil {
				var empty SubscriptionBasedUEDifferentiationInfo
				return empty, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
			}
			value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
			if !ok {
				var empty SubscriptionBasedUEDifferentiationInfo
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
			}
			return *value, nil
		},
		encode: func(value SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SubscriptionBasedUEDifferentiationInfo) UEInformationTransferIEValue {
		return UEInformationTransferIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}
	}, get: func(value *UEInformationTransferIEValue) (*SubscriptionBasedUEDifferentiationInfo, bool) {
		return value.AsSubscriptionBasedUEDifferentiationInfo()
	}}
}
func (UEInformationTransferIETable) infoPendingDataIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(283), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PendingDataIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-PendingDataIndication"}}}
}

// PendingDataIndication returns the typed binding for the PendingDataIndication row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) PendingDataIndication() UEInformationTransferPendingDataIndicationIEBinding {
	return UEInformationTransferPendingDataIndicationIEBinding{info: t.infoPendingDataIndication(), codec: func() s01.PendingDataIndicationValueCodec {
		sealed := s01.PendingDataIndicationValueCodec{}
		*s01.BridgePendingDataIndicationValueCodecFieldPath(&sealed) = "PendingDataIndication"
		*s01.BridgePendingDataIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PendingDataIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PendingDataIndication")
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(283), raw)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, runtime.WrapDecodePath(err, "PendingDataIndication")
			}
			value, ok := decoded.AsPendingDataIndication()
			if !ok {
				var empty s00.PendingDataIndication
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-PendingDataIndication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePendingDataIndicationValueCodecFieldEncode(&sealed) = func(value s00.PendingDataIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.PendingDataIndication) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s00.PendingDataIndication, bool) {
			return value.AsPendingDataIndication()
		}}
}
func (UEInformationTransferIETable) infoMaskedIMEISV() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(192), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Masked-IMEISV"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-Masked-IMEISV"}}}
}

// MaskedIMEISV returns the typed binding for the MaskedIMEISV row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) MaskedIMEISV() UEInformationTransferMaskedIMEISVIEBinding {
	return UEInformationTransferMaskedIMEISVIEBinding{info: t.infoMaskedIMEISV(), codec: func() s01.MaskedIMEISVValueCodec {
		sealed := s01.MaskedIMEISVValueCodec{}
		*s01.BridgeMaskedIMEISVValueCodecFieldPath(&sealed) = "MaskedIMEISV"
		*s01.BridgeMaskedIMEISVValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MaskedIMEISV, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MaskedIMEISV")
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(192), raw)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, runtime.WrapDecodePath(err, "MaskedIMEISV")
			}
			value, ok := decoded.AsMaskedIMEISV()
			if !ok {
				var empty s00.MaskedIMEISV
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-Masked-IMEISV: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&sealed) = func(value s00.MaskedIMEISV, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldCapture(&sealed) = func(v s00.MaskedIMEISV, options aper.DecodeState) (s00.MaskedIMEISV, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMaskedIMEISV(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldCompare(&sealed) = func(v s00.MaskedIMEISV, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMaskedIMEISV(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MaskedIMEISV"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MaskedIMEISV) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s00.MaskedIMEISV, bool) { return value.AsMaskedIMEISV() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEInformationTransferIETable.
func (t UEInformationTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEInformationTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(96):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-S-TMSI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(252):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Level-QoS-Parameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(74):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(283):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-PendingDataIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(192):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-Masked-IMEISV requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEInformationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEInformationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEInformationTransferIEField{Id: id, Criticality: criticality, Value: UEInformationTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CEModeBRestrictedCodec binds the complete APER value type.
func CEModeBRestrictedCodec() s00.CEModeBRestrictedValueCodec {
	return ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Codec()
}

// CoarseUELocationCodec binds the complete APER value type.
func CoarseUELocationCodec() s00.CoarseUELocationValueCodec {
	return ConnectionEstablishmentIndicationIEs().CoarseUELocation().Codec()
}

// ConnectedengNBItemCodec binds the complete source value type.
func ConnectedengNBItemCodec() ConnectedengNBItemValueCodec {
	return ConnectedengNBItemValueCodec{path: "ConnectedengNBItem", decode: func(data []byte, options aper.DecodeState) (ConnectedengNBItem, error) {
		var value ConnectedengNBItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ConnectedengNBItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ConnectedengNBItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ConnectedengNBItem, options aper.DecodeState) (ConnectedengNBItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APConnectedengNBItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,

			root
	}, compare: func(v ConnectedengNBItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APConnectedengNBItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectedengNBItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// DLCPSecurityInformationCodec binds the complete APER value type.
func DLCPSecurityInformationCodec() s15.DLCPSecurityInformationValueCodec {
	return ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Codec()
}

// ERABLevelQoSParametersCodec binds the complete APER value type.
func ERABLevelQoSParametersCodec() s18.ERABLevelQoSParametersValueCodec {
	return ConnectionEstablishmentIndicationIEs().UELevelQoSParameters().Codec()
}

// EndIndicationCodec binds the complete APER value type.
func EndIndicationCodec() s00.EndIndicationValueCodec {
	return ConnectionEstablishmentIndicationIEs().EndIndication().Codec()
}

// EnhancedCoverageRestrictedCodec binds the complete APER value type.
func EnhancedCoverageRestrictedCodec() s00.EnhancedCoverageRestrictedValueCodec {
	return ConnectionEstablishmentIndicationIEs().EnhancedCoverageRestricted().Codec()
}

// MaskedIMEISVCodec binds the complete APER value type.
func MaskedIMEISVCodec() s01.MaskedIMEISVValueCodec {
	return ConnectionEstablishmentIndicationIEs().MaskedIMEISV().Codec()
}

// SensorMeasConfigNameItemCodec binds the complete source value type.
func SensorMeasConfigNameItemCodec() SensorMeasConfigNameItemValueCodec {
	return SensorMeasConfigNameItemValueCodec{path: "SensorMeasConfigNameItem", decode: func(data []byte, options aper.DecodeState) (SensorMeasConfigNameItem, error) {
		var value SensorMeasConfigNameItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SensorMeasConfigNameItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SensorMeasConfigNameItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SensorMeasConfigNameItem, options aper.DecodeState) (SensorMeasConfigNameItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSensorMeasConfigNameItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v SensorMeasConfigNameItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSensorMeasConfigNameItem(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SensorMeasConfigNameItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SensorNameConfigCodec binds the complete source value type.
func SensorNameConfigCodec() SensorNameConfigValueCodec {
	return SensorNameConfigValueCodec{path: "SensorNameConfig", decode: func(data []byte, options aper.DecodeState) (s30.SensorNameConfig, error) {
		var value s30.SensorNameConfig
		if err := s30.BridgeSensorNameConfigMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s30.SensorNameConfig{}, err
		}
		*s30.BridgeSensorNameConfigFieldReceived(&value) = true
		*s30.BridgeSensorNameConfigFieldReceivedAbsolute(&value) = true
		*s30.BridgeSensorNameConfigFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s30.SensorNameConfig, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s30.BridgeSensorNameConfigMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s30.SensorNameConfig, options aper.DecodeState) (s30.SensorNameConfig, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		s30.BridgeCaptureS1APSensorNameConfig(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s30.SensorNameConfig, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s30.BridgeCompareS1APSensorNameConfig(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SensorNameConfig"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ServedDCNsItemCodec binds the complete source value type.
func ServedDCNsItemCodec() ServedDCNsItemValueCodec {
	return ServedDCNsItemValueCodec{path: "ServedDCNsItem", decode: func(data []byte, options aper.DecodeState) (ServedDCNsItem, error) {
		var value ServedDCNsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ServedDCNsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ServedDCNsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ServedDCNsItem, options aper.DecodeState) (ServedDCNsItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APServedDCNsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ServedDCNsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APServedDCNsItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedDCNsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ServedGUMMEIsItemCodec binds the complete source value type.
func ServedGUMMEIsItemCodec() ServedGUMMEIsItemValueCodec {
	return ServedGUMMEIsItemValueCodec{path: "ServedGUMMEIsItem", decode: func(data []byte, options aper.DecodeState) (ServedGUMMEIsItem, error) {
		var value ServedGUMMEIsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ServedGUMMEIsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ServedGUMMEIsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ServedGUMMEIsItem, options aper.DecodeState) (ServedGUMMEIsItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APServedGUMMEIsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root

	}, compare: func(v ServedGUMMEIsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APServedGUMMEIsItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedGUMMEIsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SourceNgRanNodeIDCodec binds the complete source value type.
func SourceNgRanNodeIDCodec() SourceNgRanNodeIDValueCodec {
	return SourceNgRanNodeIDValueCodec{path: "SourceNgRanNodeID", decode: func(data []byte, options aper.DecodeState) (SourceNgRanNodeID, error) {
		var value SourceNgRanNodeID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SourceNgRanNodeID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SourceNgRanNodeID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SourceNgRanNodeID, options aper.DecodeState) (SourceNgRanNodeID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSourceNgRanNodeID(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root

	}, compare: func(v SourceNgRanNodeID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSourceNgRanNodeID(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceNgRanNodeID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SubscriptionBasedUEDifferentiationInfoCodec binds the complete APER value type.
func SubscriptionBasedUEDifferentiationInfoCodec() SubscriptionBasedUEDifferentiationInfoValueCodec {
	return ConnectionEstablishmentIndicationIEs().SubscriptionBasedUEDifferentiationInfo().Codec()
}

// SupportedTAsItemCodec binds the complete source value type.
func SupportedTAsItemCodec() SupportedTAsItemValueCodec {
	return SupportedTAsItemValueCodec{path: "SupportedTAsItem", decode: func(data []byte, options aper.DecodeState) (SupportedTAsItem, error) {
		var value SupportedTAsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SupportedTAsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SupportedTAsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SupportedTAsItem, options aper.DecodeState) (SupportedTAsItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APSupportedTAsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SupportedTAsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSupportedTAsItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SupportedTAsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// UERadioCapabilityCodec binds the complete APER value type.
func UERadioCapabilityCodec() s02.UERadioCapabilityValueCodec {
	return ConnectionEstablishmentIndicationIEs().UERadioCapability().Codec()
}

// UERadioCapabilityIDCodec binds the complete APER value type.
func UERadioCapabilityIDCodec() s02.UERadioCapabilityIDValueCodec {
	return ConnectionEstablishmentIndicationIEs().UERadioCapabilityID().Codec()
}
func BridgeConnectedengNBItemAPERValueFieldContext(v *ConnectedengNBItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBItemAPERValueFieldReceived(v *ConnectedengNBItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectedengNBItemAPERValueFieldReplay(v *ConnectedengNBItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectedengNBItemAPERValueFieldWithoutReplay(v *ConnectedengNBItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectedengNBItemFieldExtCount(v *ConnectedengNBItem) *int64   { return &v.extCount }
func BridgeConnectedengNBItemFieldExtData(v *ConnectedengNBItem) *[][]byte { return &v.extData }
func BridgeConnectedengNBItemFieldExtOrigin(v *ConnectedengNBItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeConnectedengNBItemFieldExtPresent(v *ConnectedengNBItem) *[]bool       { return &v.extPresent }
func BridgeConnectedengNBItemFieldExtWire(v *ConnectedengNBItem) *[]aper.WireSpan { return &v.extWire }
func BridgeConnectedengNBItemFieldIEExtensionsIndef(v *ConnectedengNBItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeConnectedengNBItemFieldPerExtPadding(v *ConnectedengNBItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeConnectedengNBItemFieldPerPadding(v *ConnectedengNBItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeConnectedengNBItemFieldReceived(v *ConnectedengNBItem) *bool { return &v.received }
func BridgeConnectedengNBItemFieldReceivedAbsolute(v *ConnectedengNBItem) *bool {
	return &v.receivedAbsolute
}
func BridgeConnectedengNBItemFieldReceivedBytes(v *ConnectedengNBItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeConnectedengNBItemFieldReceivedLocation(v *ConnectedengNBItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeConnectedengNBItemFieldReplay(v *ConnectedengNBItem) *aper.Snapshot { return &v.replay }
func BridgeConnectedengNBItemFieldStream(v *ConnectedengNBItem) *aper.WireSpan { return &v.stream }
func BridgeConnectedengNBItemFieldSupportedTAsIndef(v *ConnectedengNBItem) *bool {
	return &v.supportedTAsIndef
}
func BridgeConnectedengNBItemFieldWithoutReplay(v *ConnectedengNBItem) *bool { return &v.withoutReplay }
func BridgeConnectedengNBItemMethodMarshalAPERBudget(v *ConnectedengNBItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeConnectedengNBItemMethodMarshalAPERBudgetValue(v *ConnectedengNBItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeConnectedengNBItemMethodMarshalAPERChanged(v *ConnectedengNBItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeConnectedengNBItemMethodMarshalAPERChangedValue(v *ConnectedengNBItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeConnectedengNBItemMethodMarshalAPERLegacy(v *ConnectedengNBItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeConnectedengNBItemMethodMarshalAPERNewValue(v *ConnectedengNBItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeConnectedengNBItemMethodMarshalAPERPlanned(v *ConnectedengNBItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeConnectedengNBItemMethodMarshalAPERTo(v *ConnectedengNBItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeConnectedengNBItemMethodUnmarshalAPERFrom(v *ConnectedengNBItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeConnectedengNBItemMethodUnmarshalAPERLegacy(v *ConnectedengNBItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeConnectedengNBItemMethodUnmarshalAPERWithOptions(v *ConnectedengNBItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeConnectedengNBItemValueCodecFieldCapture(v *ConnectedengNBItemValueCodec) *func(ConnectedengNBItem, aper.DecodeState) (ConnectedengNBItem, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectedengNBItemValueCodecFieldCompare(v *ConnectedengNBItemValueCodec) *func(ConnectedengNBItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectedengNBItemValueCodecFieldContext(v *ConnectedengNBItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBItemValueCodecFieldDecode(v *ConnectedengNBItemValueCodec) *func([]byte, aper.DecodeState) (ConnectedengNBItem, error) {
	return &v.decode
}
func BridgeConnectedengNBItemValueCodecFieldEncode(v *ConnectedengNBItemValueCodec) *func(ConnectedengNBItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectedengNBItemValueCodecFieldPath(v *ConnectedengNBItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectedengNBItemValueCodecMethodEncodeBudgetValue(v ConnectedengNBItemValueCodec, a0 ConnectedengNBItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectedengNBItemValueCodecMethodEncodeChanged(v ConnectedengNBItemValueCodec, a0 ConnectedengNBItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectedengNBListAPERValueFieldContext(v *ConnectedengNBListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBListAPERValueFieldReceived(v *ConnectedengNBListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectedengNBListAPERValueFieldReplay(v *ConnectedengNBListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectedengNBListAPERValueFieldWithoutReplay(v *ConnectedengNBListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectedengNBListValueCodecFieldCapture(v *ConnectedengNBListValueCodec) *func(ConnectedengNBList, aper.DecodeState) (ConnectedengNBList, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectedengNBListValueCodecFieldCompare(v *ConnectedengNBListValueCodec) *func(ConnectedengNBList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectedengNBListValueCodecFieldContext(v *ConnectedengNBListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBListValueCodecFieldDecode(v *ConnectedengNBListValueCodec) *func([]byte, aper.DecodeState) (ConnectedengNBList, error) {
	return &v.decode
}
func BridgeConnectedengNBListValueCodecFieldEncode(v *ConnectedengNBListValueCodec) *func(ConnectedengNBList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectedengNBListValueCodecFieldPath(v *ConnectedengNBListValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectedengNBListValueCodecMethodEncodeBudgetValue(v ConnectedengNBListValueCodec, a0 ConnectedengNBList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectedengNBListValueCodecMethodEncodeChanged(v ConnectedengNBListValueCodec, a0 ConnectedengNBList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationAPERValueFieldContext(v *ConnectionEstablishmentIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationAPERValueFieldReceived(v *ConnectionEstablishmentIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationAPERValueFieldReplay(v *ConnectionEstablishmentIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationCEModeBRestrictedIEBindingFieldCodec(v *ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding) *s00.CEModeBRestrictedValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationCEModeBRestrictedIEBindingFieldGet(v *ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.CEModeBRestricted, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationCEModeBRestrictedIEBindingFieldInfo(v *ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationCEModeBRestrictedIEBindingFieldInject(v *ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding) *func(s00.CEModeBRestricted) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationCoarseUELocationIEBindingFieldCodec(v *ConnectionEstablishmentIndicationCoarseUELocationIEBinding) *s00.CoarseUELocationValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationCoarseUELocationIEBindingFieldGet(v *ConnectionEstablishmentIndicationCoarseUELocationIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.CoarseUELocation, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationCoarseUELocationIEBindingFieldInfo(v *ConnectionEstablishmentIndicationCoarseUELocationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationCoarseUELocationIEBindingFieldInject(v *ConnectionEstablishmentIndicationCoarseUELocationIEBinding) *func(s00.CoarseUELocation) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationDLCPSecurityInformationIEBindingFieldCodec(v *ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) *s15.DLCPSecurityInformationValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationDLCPSecurityInformationIEBindingFieldGet(v *ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s15.DLCPSecurityInformation, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationDLCPSecurityInformationIEBindingFieldInfo(v *ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationDLCPSecurityInformationIEBindingFieldInject(v *ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) *func(s15.DLCPSecurityInformation) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationENBUES1APIDIEBindingFieldCodec(v *ConnectionEstablishmentIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationENBUES1APIDIEBindingFieldGet(v *ConnectionEstablishmentIndicationENBUES1APIDIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationENBUES1APIDIEBindingFieldInfo(v *ConnectionEstablishmentIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationENBUES1APIDIEBindingFieldInject(v *ConnectionEstablishmentIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationERABLevelQoSParametersIEBindingFieldCodec(v *ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) *s18.ERABLevelQoSParametersValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationERABLevelQoSParametersIEBindingFieldGet(v *ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s18.ERABLevelQoSParameters, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationERABLevelQoSParametersIEBindingFieldInfo(v *ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationERABLevelQoSParametersIEBindingFieldInject(v *ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) *func(s18.ERABLevelQoSParameters) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationEndIndicationIEBindingFieldCodec(v *ConnectionEstablishmentIndicationEndIndicationIEBinding) *s00.EndIndicationValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationEndIndicationIEBindingFieldGet(v *ConnectionEstablishmentIndicationEndIndicationIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.EndIndication, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationEndIndicationIEBindingFieldInfo(v *ConnectionEstablishmentIndicationEndIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationEndIndicationIEBindingFieldInject(v *ConnectionEstablishmentIndicationEndIndicationIEBinding) *func(s00.EndIndication) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBindingFieldCodec(v *ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding) *s00.EnhancedCoverageRestrictedValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBindingFieldGet(v *ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.EnhancedCoverageRestricted, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBindingFieldInfo(v *ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBindingFieldInject(v *ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding) *func(s00.EnhancedCoverageRestricted) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationFieldExtCount(v *ConnectionEstablishmentIndication) *int64 {
	return &v.extCount
}
func BridgeConnectionEstablishmentIndicationFieldExtData(v *ConnectionEstablishmentIndication) *[][]byte {
	return &v.extData
}
func BridgeConnectionEstablishmentIndicationFieldExtOrigin(v *ConnectionEstablishmentIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeConnectionEstablishmentIndicationFieldExtPresent(v *ConnectionEstablishmentIndication) *[]bool {
	return &v.extPresent
}
func BridgeConnectionEstablishmentIndicationFieldExtWire(v *ConnectionEstablishmentIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeConnectionEstablishmentIndicationFieldPerExtPadding(v *ConnectionEstablishmentIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeConnectionEstablishmentIndicationFieldPerPadding(v *ConnectionEstablishmentIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeConnectionEstablishmentIndicationFieldProtocolIEsIndef(v *ConnectionEstablishmentIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeConnectionEstablishmentIndicationFieldReceived(v *ConnectionEstablishmentIndication) *bool {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationFieldReceivedAbsolute(v *ConnectionEstablishmentIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeConnectionEstablishmentIndicationFieldReceivedBytes(v *ConnectionEstablishmentIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeConnectionEstablishmentIndicationFieldReceivedLocation(v *ConnectionEstablishmentIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeConnectionEstablishmentIndicationFieldReplay(v *ConnectionEstablishmentIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationFieldStream(v *ConnectionEstablishmentIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeConnectionEstablishmentIndicationFieldWithoutReplay(v *ConnectionEstablishmentIndication) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEContainerAPERValueFieldContext(v *ConnectionEstablishmentIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEContainerAPERValueFieldReceived(v *ConnectionEstablishmentIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEContainerAPERValueFieldReplay(v *ConnectionEstablishmentIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEContainerAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldCapture(v *ConnectionEstablishmentIndicationIEContainerValueCodec) *func(ConnectionEstablishmentIndicationIEContainer, aper.DecodeState) (ConnectionEstablishmentIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldCompare(v *ConnectionEstablishmentIndicationIEContainerValueCodec) *func(ConnectionEstablishmentIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldContext(v *ConnectionEstablishmentIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldDecode(v *ConnectionEstablishmentIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEContainer, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldEncode(v *ConnectionEstablishmentIndicationIEContainerValueCodec) *func(ConnectionEstablishmentIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldPath(v *ConnectionEstablishmentIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationIEContainerValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationIEContainerValueCodec, a0 ConnectionEstablishmentIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationIEContainerValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationIEContainerValueCodec, a0 ConnectionEstablishmentIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationIEFieldAPERValueFieldContext(v *ConnectionEstablishmentIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEFieldAPERValueFieldReceived(v *ConnectionEstablishmentIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEFieldAPERValueFieldReplay(v *ConnectionEstablishmentIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEFieldAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEFieldFieldReceived(v *ConnectionEstablishmentIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEFieldFieldReplay(v *ConnectionEstablishmentIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEFieldFieldStream(v *ConnectionEstablishmentIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeConnectionEstablishmentIndicationIEFieldFieldWithoutReplay(v *ConnectionEstablishmentIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEFieldMethodMarshalAPERTo(v *ConnectionEstablishmentIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeConnectionEstablishmentIndicationIEFieldMethodUnmarshalAPERFrom(v *ConnectionEstablishmentIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldCapture(v *ConnectionEstablishmentIndicationIEFieldValueCodec) *func(ConnectionEstablishmentIndicationIEField, aper.DecodeState) (ConnectionEstablishmentIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldCompare(v *ConnectionEstablishmentIndicationIEFieldValueCodec) *func(ConnectionEstablishmentIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldContext(v *ConnectionEstablishmentIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldDecode(v *ConnectionEstablishmentIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEField, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldEncode(v *ConnectionEstablishmentIndicationIEFieldValueCodec) *func(ConnectionEstablishmentIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldPath(v *ConnectionEstablishmentIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationIEFieldValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationIEFieldValueCodec, a0 ConnectionEstablishmentIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationIEFieldValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationIEFieldValueCodec, a0 ConnectionEstablishmentIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoCEModeBRestricted(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoCEModeBRestricted()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoCoarseUELocation(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoCoarseUELocation()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoDLCPSecurityInformation(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoDLCPSecurityInformation()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoENBUES1APID(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoEndIndication(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoEndIndication()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoEnhancedCoverageRestricted(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoEnhancedCoverageRestricted()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoMMEUES1APID(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoMaskedIMEISV(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoMaskedIMEISV()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoUELevelQoSParameters(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoUELevelQoSParameters()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoUERadioCapability(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoUERadioCapability()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoUERadioCapabilityID(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldContext(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldContext(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldPath(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationIEValueFieldId(v *ConnectionEstablishmentIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeConnectionEstablishmentIndicationIEValueFieldIsOpaque(v *ConnectionEstablishmentIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeConnectionEstablishmentIndicationIEValueFieldOpaque(v *ConnectionEstablishmentIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeConnectionEstablishmentIndicationIEValueFieldReceived(v *ConnectionEstablishmentIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEValueFieldReplay(v *ConnectionEstablishmentIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowCEModeBRestricted(v *ConnectionEstablishmentIndicationIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowCoarseUELocation(v *ConnectionEstablishmentIndicationIEValue) **s00.CoarseUELocation {
	return &v.rowCoarseUELocation
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowDLCPSecurityInformation(v *ConnectionEstablishmentIndicationIEValue) **s15.DLCPSecurityInformation {
	return &v.rowDLCPSecurityInformation
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowENBUES1APID(v *ConnectionEstablishmentIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowEndIndication(v *ConnectionEstablishmentIndicationIEValue) **s00.EndIndication {
	return &v.rowEndIndication
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowEnhancedCoverageRestricted(v *ConnectionEstablishmentIndicationIEValue) **s00.EnhancedCoverageRestricted {
	return &v.rowEnhancedCoverageRestricted
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowMMEUES1APID(v *ConnectionEstablishmentIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowMaskedIMEISV(v *ConnectionEstablishmentIndicationIEValue) **s00.MaskedIMEISV {
	return &v.rowMaskedIMEISV
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *ConnectionEstablishmentIndicationIEValue) **SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowUELevelQoSParameters(v *ConnectionEstablishmentIndicationIEValue) **s18.ERABLevelQoSParameters {
	return &v.rowUELevelQoSParameters
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapability(v *ConnectionEstablishmentIndicationIEValue) **s00.UERadioCapability {
	return &v.rowUERadioCapability
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapabilityID(v *ConnectionEstablishmentIndicationIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeConnectionEstablishmentIndicationIEValueMethodCaptureSemantics(v ConnectionEstablishmentIndicationIEValue, a0 aper.SemanticCapture) ConnectionEstablishmentIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeConnectionEstablishmentIndicationIEValueMethodCompareSemantics(v ConnectionEstablishmentIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeConnectionEstablishmentIndicationIEValueMethodDecode(v ConnectionEstablishmentIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ConnectionEstablishmentIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeConnectionEstablishmentIndicationIEValueMethodEncode(v ConnectionEstablishmentIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh(v ConnectionEstablishmentIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeConnectionEstablishmentIndicationIEValueMethodMatchesID(v ConnectionEstablishmentIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeConnectionEstablishmentIndicationIEValueMethodReason(v ConnectionEstablishmentIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeConnectionEstablishmentIndicationIEValueMethodRule(v ConnectionEstablishmentIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationMMEUES1APIDIEBindingFieldCodec(v *ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationMMEUES1APIDIEBindingFieldGet(v *ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationMMEUES1APIDIEBindingFieldInfo(v *ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationMMEUES1APIDIEBindingFieldInject(v *ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationMaskedIMEISVIEBindingFieldCodec(v *ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) *s01.MaskedIMEISVValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationMaskedIMEISVIEBindingFieldGet(v *ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.MaskedIMEISV, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationMaskedIMEISVIEBindingFieldInfo(v *ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationMaskedIMEISVIEBindingFieldInject(v *ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) *func(s00.MaskedIMEISV) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(v *ConnectionEstablishmentIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudgetValue(v *ConnectionEstablishmentIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERChanged(v *ConnectionEstablishmentIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERChangedValue(v *ConnectionEstablishmentIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERLegacy(v *ConnectionEstablishmentIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERNewValue(v *ConnectionEstablishmentIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERPlanned(v *ConnectionEstablishmentIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERTo(v *ConnectionEstablishmentIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeConnectionEstablishmentIndicationMethodUnmarshalAPERFrom(v *ConnectionEstablishmentIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeConnectionEstablishmentIndicationMethodUnmarshalAPERLegacy(v *ConnectionEstablishmentIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeConnectionEstablishmentIndicationMethodUnmarshalAPERWithOptions(v *ConnectionEstablishmentIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(v *ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) *SubscriptionBasedUEDifferentiationInfoValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(v *ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*SubscriptionBasedUEDifferentiationInfo, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(v *ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(v *ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) *func(SubscriptionBasedUEDifferentiationInfo) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIDIEBindingFieldCodec(v *ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) *s02.UERadioCapabilityIDValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIDIEBindingFieldGet(v *ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.UERadioCapabilityID, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIDIEBindingFieldInfo(v *ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIDIEBindingFieldInject(v *ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) *func(s00.UERadioCapabilityID) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIEBindingFieldCodec(v *ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) *s02.UERadioCapabilityValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIEBindingFieldGet(v *ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) *func(*ConnectionEstablishmentIndicationIEValue) (*s00.UERadioCapability, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIEBindingFieldInfo(v *ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIEBindingFieldInject(v *ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) *func(s00.UERadioCapability) ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldCapture(v *ConnectionEstablishmentIndicationValueCodec) *func(ConnectionEstablishmentIndication, aper.DecodeState) (ConnectionEstablishmentIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldCompare(v *ConnectionEstablishmentIndicationValueCodec) *func(ConnectionEstablishmentIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldContext(v *ConnectionEstablishmentIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldDecode(v *ConnectionEstablishmentIndicationValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndication, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldEncode(v *ConnectionEstablishmentIndicationValueCodec) *func(ConnectionEstablishmentIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldPath(v *ConnectionEstablishmentIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationValueCodec, a0 ConnectionEstablishmentIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationValueCodec, a0 ConnectionEstablishmentIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSensorMeasConfigNameItemAPERValueFieldContext(v *SensorMeasConfigNameItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasConfigNameItemAPERValueFieldReceived(v *SensorMeasConfigNameItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSensorMeasConfigNameItemAPERValueFieldReplay(v *SensorMeasConfigNameItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorMeasConfigNameItemAPERValueFieldWithoutReplay(v *SensorMeasConfigNameItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSensorMeasConfigNameItemFieldExtCount(v *SensorMeasConfigNameItem) *int64 {
	return &v.extCount
}
func BridgeSensorMeasConfigNameItemFieldExtData(v *SensorMeasConfigNameItem) *[][]byte {
	return &v.extData
}
func BridgeSensorMeasConfigNameItemFieldExtOrigin(v *SensorMeasConfigNameItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSensorMeasConfigNameItemFieldExtPresent(v *SensorMeasConfigNameItem) *[]bool {
	return &v.extPresent
}
func BridgeSensorMeasConfigNameItemFieldExtWire(v *SensorMeasConfigNameItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSensorMeasConfigNameItemFieldIEExtensionsIndef(v *SensorMeasConfigNameItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSensorMeasConfigNameItemFieldPerExtPadding(v *SensorMeasConfigNameItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSensorMeasConfigNameItemFieldPerPadding(v *SensorMeasConfigNameItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSensorMeasConfigNameItemFieldReceived(v *SensorMeasConfigNameItem) *bool {
	return &v.received
}
func BridgeSensorMeasConfigNameItemFieldReceivedAbsolute(v *SensorMeasConfigNameItem) *bool {
	return &v.receivedAbsolute
}
func BridgeSensorMeasConfigNameItemFieldReceivedBytes(v *SensorMeasConfigNameItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSensorMeasConfigNameItemFieldReceivedLocation(v *SensorMeasConfigNameItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeSensorMeasConfigNameItemFieldReplay(v *SensorMeasConfigNameItem) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorMeasConfigNameItemFieldStream(v *SensorMeasConfigNameItem) *aper.WireSpan {
	return &v.stream
}
func BridgeSensorMeasConfigNameItemFieldWithoutReplay(v *SensorMeasConfigNameItem) *bool {
	return &v.withoutReplay
}
func BridgeSensorMeasConfigNameItemMethodMarshalAPERBudget(v *SensorMeasConfigNameItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSensorMeasConfigNameItemMethodMarshalAPERBudgetValue(v *SensorMeasConfigNameItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSensorMeasConfigNameItemMethodMarshalAPERChanged(v *SensorMeasConfigNameItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSensorMeasConfigNameItemMethodMarshalAPERChangedValue(v *SensorMeasConfigNameItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSensorMeasConfigNameItemMethodMarshalAPERLegacy(v *SensorMeasConfigNameItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSensorMeasConfigNameItemMethodMarshalAPERNewValue(v *SensorMeasConfigNameItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSensorMeasConfigNameItemMethodMarshalAPERPlanned(v *SensorMeasConfigNameItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSensorMeasConfigNameItemMethodMarshalAPERTo(v *SensorMeasConfigNameItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSensorMeasConfigNameItemMethodUnmarshalAPERFrom(v *SensorMeasConfigNameItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSensorMeasConfigNameItemMethodUnmarshalAPERLegacy(v *SensorMeasConfigNameItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSensorMeasConfigNameItemMethodUnmarshalAPERWithOptions(v *SensorMeasConfigNameItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSensorMeasConfigNameItemValueCodecFieldCapture(v *SensorMeasConfigNameItemValueCodec) *func(SensorMeasConfigNameItem, aper.DecodeState) (SensorMeasConfigNameItem, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorMeasConfigNameItemValueCodecFieldCompare(v *SensorMeasConfigNameItemValueCodec) *func(SensorMeasConfigNameItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorMeasConfigNameItemValueCodecFieldContext(v *SensorMeasConfigNameItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasConfigNameItemValueCodecFieldDecode(v *SensorMeasConfigNameItemValueCodec) *func([]byte, aper.DecodeState) (SensorMeasConfigNameItem, error) {
	return &v.decode
}
func BridgeSensorMeasConfigNameItemValueCodecFieldEncode(v *SensorMeasConfigNameItemValueCodec) *func(SensorMeasConfigNameItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorMeasConfigNameItemValueCodecFieldPath(v *SensorMeasConfigNameItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorMeasConfigNameItemValueCodecMethodEncodeBudgetValue(v SensorMeasConfigNameItemValueCodec, a0 SensorMeasConfigNameItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSensorMeasConfigNameItemValueCodecMethodEncodeChanged(v SensorMeasConfigNameItemValueCodec, a0 SensorMeasConfigNameItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSensorMeasConfigNameListAPERValueFieldContext(v *SensorMeasConfigNameListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasConfigNameListAPERValueFieldReceived(v *SensorMeasConfigNameListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSensorMeasConfigNameListAPERValueFieldReplay(v *SensorMeasConfigNameListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorMeasConfigNameListAPERValueFieldWithoutReplay(v *SensorMeasConfigNameListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSensorMeasConfigNameListValueCodecFieldCapture(v *SensorMeasConfigNameListValueCodec) *func(SensorMeasConfigNameList, aper.DecodeState) (SensorMeasConfigNameList, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorMeasConfigNameListValueCodecFieldCompare(v *SensorMeasConfigNameListValueCodec) *func(SensorMeasConfigNameList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorMeasConfigNameListValueCodecFieldContext(v *SensorMeasConfigNameListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasConfigNameListValueCodecFieldDecode(v *SensorMeasConfigNameListValueCodec) *func([]byte, aper.DecodeState) (SensorMeasConfigNameList, error) {
	return &v.decode
}
func BridgeSensorMeasConfigNameListValueCodecFieldEncode(v *SensorMeasConfigNameListValueCodec) *func(SensorMeasConfigNameList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorMeasConfigNameListValueCodecFieldPath(v *SensorMeasConfigNameListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorMeasConfigNameListValueCodecMethodEncodeBudgetValue(v SensorMeasConfigNameListValueCodec, a0 SensorMeasConfigNameList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSensorMeasConfigNameListValueCodecMethodEncodeChanged(v SensorMeasConfigNameListValueCodec, a0 SensorMeasConfigNameList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSensorMeasurementConfigurationAPERValueFieldContext(v *SensorMeasurementConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasurementConfigurationAPERValueFieldReceived(v *SensorMeasurementConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSensorMeasurementConfigurationAPERValueFieldReplay(v *SensorMeasurementConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorMeasurementConfigurationAPERValueFieldWithoutReplay(v *SensorMeasurementConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSensorMeasurementConfigurationFieldExtCount(v *SensorMeasurementConfiguration) *int64 {
	return &v.extCount
}
func BridgeSensorMeasurementConfigurationFieldExtData(v *SensorMeasurementConfiguration) *[][]byte {
	return &v.extData
}
func BridgeSensorMeasurementConfigurationFieldExtOrigin(v *SensorMeasurementConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSensorMeasurementConfigurationFieldExtPresent(v *SensorMeasurementConfiguration) *[]bool {
	return &v.extPresent
}
func BridgeSensorMeasurementConfigurationFieldExtWire(v *SensorMeasurementConfiguration) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSensorMeasurementConfigurationFieldIEExtensionsIndef(v *SensorMeasurementConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSensorMeasurementConfigurationFieldPerExtPadding(v *SensorMeasurementConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSensorMeasurementConfigurationFieldPerPadding(v *SensorMeasurementConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSensorMeasurementConfigurationFieldReceived(v *SensorMeasurementConfiguration) *bool {
	return &v.received
}
func BridgeSensorMeasurementConfigurationFieldReceivedAbsolute(v *SensorMeasurementConfiguration) *bool {
	return &v.receivedAbsolute
}
func BridgeSensorMeasurementConfigurationFieldReceivedBytes(v *SensorMeasurementConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSensorMeasurementConfigurationFieldReceivedLocation(v *SensorMeasurementConfiguration) *aper.Location {
	return &v.receivedLocation
}
func BridgeSensorMeasurementConfigurationFieldReplay(v *SensorMeasurementConfiguration) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorMeasurementConfigurationFieldSensorMeasConfigNameListIndef(v *SensorMeasurementConfiguration) *bool {
	return &v.sensorMeasConfigNameListIndef
}
func BridgeSensorMeasurementConfigurationFieldStream(v *SensorMeasurementConfiguration) *aper.WireSpan {
	return &v.stream
}
func BridgeSensorMeasurementConfigurationFieldWithoutReplay(v *SensorMeasurementConfiguration) *bool {
	return &v.withoutReplay
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERBudget(v *SensorMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERBudgetValue(v *SensorMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERChanged(v *SensorMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERChangedValue(v *SensorMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERLegacy(v *SensorMeasurementConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERNewValue(v *SensorMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERPlanned(v *SensorMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERTo(v *SensorMeasurementConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSensorMeasurementConfigurationMethodUnmarshalAPERFrom(v *SensorMeasurementConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSensorMeasurementConfigurationMethodUnmarshalAPERLegacy(v *SensorMeasurementConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSensorMeasurementConfigurationMethodUnmarshalAPERWithOptions(v *SensorMeasurementConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSensorMeasurementConfigurationValueCodecFieldCapture(v *SensorMeasurementConfigurationValueCodec) *func(SensorMeasurementConfiguration, aper.DecodeState) (SensorMeasurementConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorMeasurementConfigurationValueCodecFieldCompare(v *SensorMeasurementConfigurationValueCodec) *func(SensorMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorMeasurementConfigurationValueCodecFieldContext(v *SensorMeasurementConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasurementConfigurationValueCodecFieldDecode(v *SensorMeasurementConfigurationValueCodec) *func([]byte, aper.DecodeState) (SensorMeasurementConfiguration, error) {
	return &v.decode
}
func BridgeSensorMeasurementConfigurationValueCodecFieldEncode(v *SensorMeasurementConfigurationValueCodec) *func(SensorMeasurementConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorMeasurementConfigurationValueCodecFieldPath(v *SensorMeasurementConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorMeasurementConfigurationValueCodecMethodEncodeBudgetValue(v SensorMeasurementConfigurationValueCodec, a0 SensorMeasurementConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSensorMeasurementConfigurationValueCodecMethodEncodeChanged(v SensorMeasurementConfigurationValueCodec, a0 SensorMeasurementConfiguration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSensorNameConfigAPERValueFieldContext(v *SensorNameConfigAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorNameConfigAPERValueFieldReceived(v *SensorNameConfigAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSensorNameConfigAPERValueFieldReplay(v *SensorNameConfigAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorNameConfigAPERValueFieldWithoutReplay(v *SensorNameConfigAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSensorNameConfigValueCodecFieldCapture(v *SensorNameConfigValueCodec) *func(s30.SensorNameConfig, aper.DecodeState) (s30.SensorNameConfig, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorNameConfigValueCodecFieldCompare(v *SensorNameConfigValueCodec) *func(s30.SensorNameConfig, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorNameConfigValueCodecFieldContext(v *SensorNameConfigValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorNameConfigValueCodecFieldDecode(v *SensorNameConfigValueCodec) *func([]byte, aper.DecodeState) (s30.SensorNameConfig, error) {
	return &v.decode
}
func BridgeSensorNameConfigValueCodecFieldEncode(v *SensorNameConfigValueCodec) *func(s30.SensorNameConfig, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorNameConfigValueCodecFieldPath(v *SensorNameConfigValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorNameConfigValueCodecMethodEncodeBudgetValue(v SensorNameConfigValueCodec, a0 s30.SensorNameConfig, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSensorNameConfigValueCodecMethodEncodeChanged(v SensorNameConfigValueCodec, a0 s30.SensorNameConfig, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeServedDCNsAPERValueFieldContext(v *ServedDCNsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedDCNsAPERValueFieldReceived(v *ServedDCNsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeServedDCNsAPERValueFieldReplay(v *ServedDCNsAPERValue) *aper.Snapshot { return &v.replay }
func BridgeServedDCNsAPERValueFieldWithoutReplay(v *ServedDCNsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeServedDCNsItemAPERValueFieldContext(v *ServedDCNsItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedDCNsItemAPERValueFieldReceived(v *ServedDCNsItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeServedDCNsItemAPERValueFieldReplay(v *ServedDCNsItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeServedDCNsItemAPERValueFieldWithoutReplay(v *ServedDCNsItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeServedDCNsItemFieldExtCount(v *ServedDCNsItem) *int64                { return &v.extCount }
func BridgeServedDCNsItemFieldExtData(v *ServedDCNsItem) *[][]byte              { return &v.extData }
func BridgeServedDCNsItemFieldExtOrigin(v *ServedDCNsItem) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeServedDCNsItemFieldExtPresent(v *ServedDCNsItem) *[]bool             { return &v.extPresent }
func BridgeServedDCNsItemFieldExtWire(v *ServedDCNsItem) *[]aper.WireSpan       { return &v.extWire }
func BridgeServedDCNsItemFieldIEExtensionsIndef(v *ServedDCNsItem) *bool        { return &v.iEExtensionsIndef }
func BridgeServedDCNsItemFieldPerExtPadding(v *ServedDCNsItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeServedDCNsItemFieldPerPadding(v *ServedDCNsItem) *aper.FinalPadding { return &v.perPadding }
func BridgeServedDCNsItemFieldReceived(v *ServedDCNsItem) *bool                { return &v.received }
func BridgeServedDCNsItemFieldReceivedAbsolute(v *ServedDCNsItem) *bool        { return &v.receivedAbsolute }
func BridgeServedDCNsItemFieldReceivedBytes(v *ServedDCNsItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeServedDCNsItemFieldReceivedLocation(v *ServedDCNsItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeServedDCNsItemFieldReplay(v *ServedDCNsItem) *aper.Snapshot { return &v.replay }
func BridgeServedDCNsItemFieldStream(v *ServedDCNsItem) *aper.WireSpan { return &v.stream }
func BridgeServedDCNsItemFieldWithoutReplay(v *ServedDCNsItem) *bool   { return &v.withoutReplay }
func BridgeServedDCNsItemMethodMarshalAPERBudget(v *ServedDCNsItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeServedDCNsItemMethodMarshalAPERBudgetValue(v *ServedDCNsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeServedDCNsItemMethodMarshalAPERChanged(v *ServedDCNsItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeServedDCNsItemMethodMarshalAPERChangedValue(v *ServedDCNsItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeServedDCNsItemMethodMarshalAPERLegacy(v *ServedDCNsItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeServedDCNsItemMethodMarshalAPERNewValue(v *ServedDCNsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeServedDCNsItemMethodMarshalAPERPlanned(v *ServedDCNsItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeServedDCNsItemMethodMarshalAPERTo(v *ServedDCNsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeServedDCNsItemMethodUnmarshalAPERFrom(v *ServedDCNsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeServedDCNsItemMethodUnmarshalAPERLegacy(v *ServedDCNsItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeServedDCNsItemMethodUnmarshalAPERWithOptions(v *ServedDCNsItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeServedDCNsItemValueCodecFieldCapture(v *ServedDCNsItemValueCodec) *func(ServedDCNsItem, aper.DecodeState) (ServedDCNsItem, aper.Snapshot) {
	return &v.capture
}
func BridgeServedDCNsItemValueCodecFieldCompare(v *ServedDCNsItemValueCodec) *func(ServedDCNsItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedDCNsItemValueCodecFieldContext(v *ServedDCNsItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedDCNsItemValueCodecFieldDecode(v *ServedDCNsItemValueCodec) *func([]byte, aper.DecodeState) (ServedDCNsItem, error) {
	return &v.decode
}
func BridgeServedDCNsItemValueCodecFieldEncode(v *ServedDCNsItemValueCodec) *func(ServedDCNsItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedDCNsItemValueCodecFieldPath(v *ServedDCNsItemValueCodec) *aper.Path { return &v.path }
func BridgeServedDCNsItemValueCodecMethodEncodeBudgetValue(v ServedDCNsItemValueCodec, a0 ServedDCNsItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeServedDCNsItemValueCodecMethodEncodeChanged(v ServedDCNsItemValueCodec, a0 ServedDCNsItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeServedDCNsValueCodecFieldCapture(v *ServedDCNsValueCodec) *func(ServedDCNs, aper.DecodeState) (ServedDCNs, aper.Snapshot) {
	return &v.capture
}
func BridgeServedDCNsValueCodecFieldCompare(v *ServedDCNsValueCodec) *func(ServedDCNs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedDCNsValueCodecFieldContext(v *ServedDCNsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedDCNsValueCodecFieldDecode(v *ServedDCNsValueCodec) *func([]byte, aper.DecodeState) (ServedDCNs, error) {
	return &v.decode
}
func BridgeServedDCNsValueCodecFieldEncode(v *ServedDCNsValueCodec) *func(ServedDCNs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedDCNsValueCodecFieldPath(v *ServedDCNsValueCodec) *aper.Path { return &v.path }
func BridgeServedDCNsValueCodecMethodEncodeBudgetValue(v ServedDCNsValueCodec, a0 ServedDCNs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeServedDCNsValueCodecMethodEncodeChanged(v ServedDCNsValueCodec, a0 ServedDCNs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeServedGUMMEIsAPERValueFieldContext(v *ServedGUMMEIsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedGUMMEIsAPERValueFieldReceived(v *ServedGUMMEIsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeServedGUMMEIsAPERValueFieldReplay(v *ServedGUMMEIsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeServedGUMMEIsAPERValueFieldWithoutReplay(v *ServedGUMMEIsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeServedGUMMEIsItemAPERValueFieldContext(v *ServedGUMMEIsItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedGUMMEIsItemAPERValueFieldReceived(v *ServedGUMMEIsItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeServedGUMMEIsItemAPERValueFieldReplay(v *ServedGUMMEIsItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeServedGUMMEIsItemAPERValueFieldWithoutReplay(v *ServedGUMMEIsItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeServedGUMMEIsItemFieldExtCount(v *ServedGUMMEIsItem) *int64   { return &v.extCount }
func BridgeServedGUMMEIsItemFieldExtData(v *ServedGUMMEIsItem) *[][]byte { return &v.extData }
func BridgeServedGUMMEIsItemFieldExtOrigin(v *ServedGUMMEIsItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeServedGUMMEIsItemFieldExtPresent(v *ServedGUMMEIsItem) *[]bool       { return &v.extPresent }
func BridgeServedGUMMEIsItemFieldExtWire(v *ServedGUMMEIsItem) *[]aper.WireSpan { return &v.extWire }
func BridgeServedGUMMEIsItemFieldIEExtensionsIndef(v *ServedGUMMEIsItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeServedGUMMEIsItemFieldPerExtPadding(v *ServedGUMMEIsItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeServedGUMMEIsItemFieldPerPadding(v *ServedGUMMEIsItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeServedGUMMEIsItemFieldReceived(v *ServedGUMMEIsItem) *bool { return &v.received }
func BridgeServedGUMMEIsItemFieldReceivedAbsolute(v *ServedGUMMEIsItem) *bool {
	return &v.receivedAbsolute
}
func BridgeServedGUMMEIsItemFieldReceivedBytes(v *ServedGUMMEIsItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeServedGUMMEIsItemFieldReceivedLocation(v *ServedGUMMEIsItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeServedGUMMEIsItemFieldReplay(v *ServedGUMMEIsItem) *aper.Snapshot { return &v.replay }
func BridgeServedGUMMEIsItemFieldServedGroupIDsIndef(v *ServedGUMMEIsItem) *bool {
	return &v.servedGroupIDsIndef
}
func BridgeServedGUMMEIsItemFieldServedMMECsIndef(v *ServedGUMMEIsItem) *bool {
	return &v.servedMMECsIndef
}
func BridgeServedGUMMEIsItemFieldServedPLMNsIndef(v *ServedGUMMEIsItem) *bool {
	return &v.servedPLMNsIndef
}
func BridgeServedGUMMEIsItemFieldStream(v *ServedGUMMEIsItem) *aper.WireSpan { return &v.stream }
func BridgeServedGUMMEIsItemFieldWithoutReplay(v *ServedGUMMEIsItem) *bool   { return &v.withoutReplay }
func BridgeServedGUMMEIsItemMethodMarshalAPERBudget(v *ServedGUMMEIsItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeServedGUMMEIsItemMethodMarshalAPERBudgetValue(v *ServedGUMMEIsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeServedGUMMEIsItemMethodMarshalAPERChanged(v *ServedGUMMEIsItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeServedGUMMEIsItemMethodMarshalAPERChangedValue(v *ServedGUMMEIsItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeServedGUMMEIsItemMethodMarshalAPERLegacy(v *ServedGUMMEIsItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeServedGUMMEIsItemMethodMarshalAPERNewValue(v *ServedGUMMEIsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeServedGUMMEIsItemMethodMarshalAPERPlanned(v *ServedGUMMEIsItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeServedGUMMEIsItemMethodMarshalAPERTo(v *ServedGUMMEIsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeServedGUMMEIsItemMethodUnmarshalAPERFrom(v *ServedGUMMEIsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeServedGUMMEIsItemMethodUnmarshalAPERLegacy(v *ServedGUMMEIsItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeServedGUMMEIsItemMethodUnmarshalAPERWithOptions(v *ServedGUMMEIsItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeServedGUMMEIsItemValueCodecFieldCapture(v *ServedGUMMEIsItemValueCodec) *func(ServedGUMMEIsItem, aper.DecodeState) (ServedGUMMEIsItem, aper.Snapshot) {
	return &v.capture
}
func BridgeServedGUMMEIsItemValueCodecFieldCompare(v *ServedGUMMEIsItemValueCodec) *func(ServedGUMMEIsItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedGUMMEIsItemValueCodecFieldContext(v *ServedGUMMEIsItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedGUMMEIsItemValueCodecFieldDecode(v *ServedGUMMEIsItemValueCodec) *func([]byte, aper.DecodeState) (ServedGUMMEIsItem, error) {
	return &v.decode
}
func BridgeServedGUMMEIsItemValueCodecFieldEncode(v *ServedGUMMEIsItemValueCodec) *func(ServedGUMMEIsItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedGUMMEIsItemValueCodecFieldPath(v *ServedGUMMEIsItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeServedGUMMEIsItemValueCodecMethodEncodeBudgetValue(v ServedGUMMEIsItemValueCodec, a0 ServedGUMMEIsItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeServedGUMMEIsItemValueCodecMethodEncodeChanged(v ServedGUMMEIsItemValueCodec, a0 ServedGUMMEIsItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeServedGUMMEIsValueCodecFieldCapture(v *ServedGUMMEIsValueCodec) *func(ServedGUMMEIs, aper.DecodeState) (ServedGUMMEIs, aper.Snapshot) {
	return &v.capture
}
func BridgeServedGUMMEIsValueCodecFieldCompare(v *ServedGUMMEIsValueCodec) *func(ServedGUMMEIs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedGUMMEIsValueCodecFieldContext(v *ServedGUMMEIsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedGUMMEIsValueCodecFieldDecode(v *ServedGUMMEIsValueCodec) *func([]byte, aper.DecodeState) (ServedGUMMEIs, error) {
	return &v.decode
}
func BridgeServedGUMMEIsValueCodecFieldEncode(v *ServedGUMMEIsValueCodec) *func(ServedGUMMEIs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedGUMMEIsValueCodecFieldPath(v *ServedGUMMEIsValueCodec) *aper.Path { return &v.path }
func BridgeServedGUMMEIsValueCodecMethodEncodeBudgetValue(v ServedGUMMEIsValueCodec, a0 ServedGUMMEIs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeServedGUMMEIsValueCodecMethodEncodeChanged(v ServedGUMMEIsValueCodec, a0 ServedGUMMEIs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSourceNgRanNodeIDAPERValueFieldContext(v *SourceNgRanNodeIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNgRanNodeIDAPERValueFieldReceived(v *SourceNgRanNodeIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSourceNgRanNodeIDAPERValueFieldReplay(v *SourceNgRanNodeIDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceNgRanNodeIDAPERValueFieldWithoutReplay(v *SourceNgRanNodeIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSourceNgRanNodeIDFieldExtCount(v *SourceNgRanNodeID) *int64   { return &v.extCount }
func BridgeSourceNgRanNodeIDFieldExtData(v *SourceNgRanNodeID) *[][]byte { return &v.extData }
func BridgeSourceNgRanNodeIDFieldExtOrigin(v *SourceNgRanNodeID) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSourceNgRanNodeIDFieldExtPresent(v *SourceNgRanNodeID) *[]bool       { return &v.extPresent }
func BridgeSourceNgRanNodeIDFieldExtWire(v *SourceNgRanNodeID) *[]aper.WireSpan { return &v.extWire }
func BridgeSourceNgRanNodeIDFieldIEExtensionsIndef(v *SourceNgRanNodeID) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSourceNgRanNodeIDFieldPerExtPadding(v *SourceNgRanNodeID) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSourceNgRanNodeIDFieldPerPadding(v *SourceNgRanNodeID) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSourceNgRanNodeIDFieldReceived(v *SourceNgRanNodeID) *bool { return &v.received }
func BridgeSourceNgRanNodeIDFieldReceivedAbsolute(v *SourceNgRanNodeID) *bool {
	return &v.receivedAbsolute
}
func BridgeSourceNgRanNodeIDFieldReceivedBytes(v *SourceNgRanNodeID) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSourceNgRanNodeIDFieldReceivedLocation(v *SourceNgRanNodeID) *aper.Location {
	return &v.receivedLocation
}
func BridgeSourceNgRanNodeIDFieldReplay(v *SourceNgRanNodeID) *aper.Snapshot { return &v.replay }
func BridgeSourceNgRanNodeIDFieldStream(v *SourceNgRanNodeID) *aper.WireSpan { return &v.stream }
func BridgeSourceNgRanNodeIDFieldWithoutReplay(v *SourceNgRanNodeID) *bool   { return &v.withoutReplay }
func BridgeSourceNgRanNodeIDMethodMarshalAPERBudget(v *SourceNgRanNodeID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSourceNgRanNodeIDMethodMarshalAPERBudgetValue(v *SourceNgRanNodeID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSourceNgRanNodeIDMethodMarshalAPERChanged(v *SourceNgRanNodeID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSourceNgRanNodeIDMethodMarshalAPERChangedValue(v *SourceNgRanNodeID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSourceNgRanNodeIDMethodMarshalAPERLegacy(v *SourceNgRanNodeID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSourceNgRanNodeIDMethodMarshalAPERNewValue(v *SourceNgRanNodeID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSourceNgRanNodeIDMethodMarshalAPERPlanned(v *SourceNgRanNodeID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSourceNgRanNodeIDMethodMarshalAPERTo(v *SourceNgRanNodeID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceNgRanNodeIDMethodUnmarshalAPERFrom(v *SourceNgRanNodeID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceNgRanNodeIDMethodUnmarshalAPERLegacy(v *SourceNgRanNodeID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSourceNgRanNodeIDMethodUnmarshalAPERWithOptions(v *SourceNgRanNodeID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSourceNgRanNodeIDValueCodecFieldCapture(v *SourceNgRanNodeIDValueCodec) *func(SourceNgRanNodeID, aper.DecodeState) (SourceNgRanNodeID, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNgRanNodeIDValueCodecFieldCompare(v *SourceNgRanNodeIDValueCodec) *func(SourceNgRanNodeID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNgRanNodeIDValueCodecFieldContext(v *SourceNgRanNodeIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNgRanNodeIDValueCodecFieldDecode(v *SourceNgRanNodeIDValueCodec) *func([]byte, aper.DecodeState) (SourceNgRanNodeID, error) {
	return &v.decode
}
func BridgeSourceNgRanNodeIDValueCodecFieldEncode(v *SourceNgRanNodeIDValueCodec) *func(SourceNgRanNodeID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNgRanNodeIDValueCodecFieldPath(v *SourceNgRanNodeIDValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNgRanNodeIDValueCodecMethodEncodeBudgetValue(v SourceNgRanNodeIDValueCodec, a0 SourceNgRanNodeID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSourceNgRanNodeIDValueCodecMethodEncodeChanged(v SourceNgRanNodeIDValueCodec, a0 SourceNgRanNodeID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSourceNodeIDAPERValueFieldContext(v *SourceNodeIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDAPERValueFieldReceived(v *SourceNodeIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSourceNodeIDAPERValueFieldReplay(v *SourceNodeIDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceNodeIDAPERValueFieldWithoutReplay(v *SourceNodeIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSourceNodeIDFieldPerOpenTypePadding(v *SourceNodeID) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSourceNodeIDFieldPerPadding(v *SourceNodeID) *aper.CompletePadding { return &v.perPadding }
func BridgeSourceNodeIDFieldReceived(v *SourceNodeID) *bool                   { return &v.received }
func BridgeSourceNodeIDFieldReceivedAbsolute(v *SourceNodeID) *bool           { return &v.receivedAbsolute }
func BridgeSourceNodeIDFieldReceivedBytes(v *SourceNodeID) *aper.WireSpan     { return &v.receivedBytes }
func BridgeSourceNodeIDFieldReceivedLocation(v *SourceNodeID) *aper.Location {
	return &v.receivedLocation
}
func BridgeSourceNodeIDFieldReplay(v *SourceNodeID) *aper.Snapshot { return &v.replay }
func BridgeSourceNodeIDFieldStream(v *SourceNodeID) *aper.WireSpan { return &v.stream }
func BridgeSourceNodeIDFieldWithoutReplay(v *SourceNodeID) *bool   { return &v.withoutReplay }
func BridgeSourceNodeIDMethodMarshalAPERBudget(v *SourceNodeID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSourceNodeIDMethodMarshalAPERBudgetValue(v *SourceNodeID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSourceNodeIDMethodMarshalAPERChanged(v *SourceNodeID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSourceNodeIDMethodMarshalAPERChangedValue(v *SourceNodeID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSourceNodeIDMethodMarshalAPERLegacy(v *SourceNodeID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSourceNodeIDMethodMarshalAPERNewValue(v *SourceNodeID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSourceNodeIDMethodMarshalAPERPlanned(v *SourceNodeID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSourceNodeIDMethodMarshalAPERTo(v *SourceNodeID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceNodeIDMethodUnmarshalAPERFrom(v *SourceNodeID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceNodeIDMethodUnmarshalAPERLegacy(v *SourceNodeID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSourceNodeIDMethodUnmarshalAPERWithOptions(v *SourceNodeID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSourceNodeIDValueCodecFieldCapture(v *SourceNodeIDValueCodec) *func(SourceNodeID, aper.DecodeState) (SourceNodeID, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNodeIDValueCodecFieldCompare(v *SourceNodeIDValueCodec) *func(SourceNodeID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNodeIDValueCodecFieldContext(v *SourceNodeIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDValueCodecFieldDecode(v *SourceNodeIDValueCodec) *func([]byte, aper.DecodeState) (SourceNodeID, error) {
	return &v.decode
}
func BridgeSourceNodeIDValueCodecFieldEncode(v *SourceNodeIDValueCodec) *func(SourceNodeID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNodeIDValueCodecFieldPath(v *SourceNodeIDValueCodec) *aper.Path { return &v.path }
func BridgeSourceNodeIDValueCodecMethodEncodeBudgetValue(v SourceNodeIDValueCodec, a0 SourceNodeID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSourceNodeIDValueCodecMethodEncodeChanged(v SourceNodeIDValueCodec, a0 SourceNodeID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSubscriptionBasedUEDifferentiationInfoAPERValueFieldContext(v *SubscriptionBasedUEDifferentiationInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubscriptionBasedUEDifferentiationInfoAPERValueFieldReceived(v *SubscriptionBasedUEDifferentiationInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSubscriptionBasedUEDifferentiationInfoAPERValueFieldReplay(v *SubscriptionBasedUEDifferentiationInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSubscriptionBasedUEDifferentiationInfoAPERValueFieldWithoutReplay(v *SubscriptionBasedUEDifferentiationInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldExtCount(v *SubscriptionBasedUEDifferentiationInfo) *int64 {
	return &v.extCount
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldExtData(v *SubscriptionBasedUEDifferentiationInfo) *[][]byte {
	return &v.extData
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldExtOrigin(v *SubscriptionBasedUEDifferentiationInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldExtPresent(v *SubscriptionBasedUEDifferentiationInfo) *[]bool {
	return &v.extPresent
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldExtWire(v *SubscriptionBasedUEDifferentiationInfo) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldIEExtensionsIndef(v *SubscriptionBasedUEDifferentiationInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldPerExtPadding(v *SubscriptionBasedUEDifferentiationInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldPerPadding(v *SubscriptionBasedUEDifferentiationInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldReceived(v *SubscriptionBasedUEDifferentiationInfo) *bool {
	return &v.received
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedAbsolute(v *SubscriptionBasedUEDifferentiationInfo) *bool {
	return &v.receivedAbsolute
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedBytes(v *SubscriptionBasedUEDifferentiationInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedLocation(v *SubscriptionBasedUEDifferentiationInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldReplay(v *SubscriptionBasedUEDifferentiationInfo) *aper.Snapshot {
	return &v.replay
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldStream(v *SubscriptionBasedUEDifferentiationInfo) *aper.WireSpan {
	return &v.stream
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldWithoutReplay(v *SubscriptionBasedUEDifferentiationInfo) *bool {
	return &v.withoutReplay
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudget(v *SubscriptionBasedUEDifferentiationInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudgetValue(v *SubscriptionBasedUEDifferentiationInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERChanged(v *SubscriptionBasedUEDifferentiationInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERChangedValue(v *SubscriptionBasedUEDifferentiationInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERLegacy(v *SubscriptionBasedUEDifferentiationInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERNewValue(v *SubscriptionBasedUEDifferentiationInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERPlanned(v *SubscriptionBasedUEDifferentiationInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERTo(v *SubscriptionBasedUEDifferentiationInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERFrom(v *SubscriptionBasedUEDifferentiationInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERLegacy(v *SubscriptionBasedUEDifferentiationInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERWithOptions(v *SubscriptionBasedUEDifferentiationInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCapture(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *func(SubscriptionBasedUEDifferentiationInfo, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCompare(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *func(SubscriptionBasedUEDifferentiationInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldContext(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldDecode(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *func([]byte, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfo, error) {
	return &v.decode
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *func(SubscriptionBasedUEDifferentiationInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldPath(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecMethodEncodeBudgetValue(v SubscriptionBasedUEDifferentiationInfoValueCodec, a0 SubscriptionBasedUEDifferentiationInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecMethodEncodeChanged(v SubscriptionBasedUEDifferentiationInfoValueCodec, a0 SubscriptionBasedUEDifferentiationInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSupportedTAsAPERValueFieldContext(v *SupportedTAsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsAPERValueFieldReceived(v *SupportedTAsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSupportedTAsAPERValueFieldReplay(v *SupportedTAsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSupportedTAsAPERValueFieldWithoutReplay(v *SupportedTAsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSupportedTAsItemAPERValueFieldContext(v *SupportedTAsItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsItemAPERValueFieldReceived(v *SupportedTAsItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSupportedTAsItemAPERValueFieldReplay(v *SupportedTAsItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSupportedTAsItemAPERValueFieldWithoutReplay(v *SupportedTAsItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSupportedTAsItemFieldBroadcastPLMNsIndef(v *SupportedTAsItem) *bool {
	return &v.broadcastPLMNsIndef
}
func BridgeSupportedTAsItemFieldExtCount(v *SupportedTAsItem) *int64   { return &v.extCount }
func BridgeSupportedTAsItemFieldExtData(v *SupportedTAsItem) *[][]byte { return &v.extData }
func BridgeSupportedTAsItemFieldExtOrigin(v *SupportedTAsItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSupportedTAsItemFieldExtPresent(v *SupportedTAsItem) *[]bool       { return &v.extPresent }
func BridgeSupportedTAsItemFieldExtWire(v *SupportedTAsItem) *[]aper.WireSpan { return &v.extWire }
func BridgeSupportedTAsItemFieldIEExtensionsIndef(v *SupportedTAsItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSupportedTAsItemFieldPerExtPadding(v *SupportedTAsItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSupportedTAsItemFieldPerPadding(v *SupportedTAsItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSupportedTAsItemFieldReceived(v *SupportedTAsItem) *bool { return &v.received }
func BridgeSupportedTAsItemFieldReceivedAbsolute(v *SupportedTAsItem) *bool {
	return &v.receivedAbsolute
}
func BridgeSupportedTAsItemFieldReceivedBytes(v *SupportedTAsItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSupportedTAsItemFieldReceivedLocation(v *SupportedTAsItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeSupportedTAsItemFieldReplay(v *SupportedTAsItem) *aper.Snapshot { return &v.replay }
func BridgeSupportedTAsItemFieldStream(v *SupportedTAsItem) *aper.WireSpan { return &v.stream }
func BridgeSupportedTAsItemFieldWithoutReplay(v *SupportedTAsItem) *bool   { return &v.withoutReplay }
func BridgeSupportedTAsItemMethodMarshalAPERBudget(v *SupportedTAsItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSupportedTAsItemMethodMarshalAPERBudgetValue(v *SupportedTAsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSupportedTAsItemMethodMarshalAPERChanged(v *SupportedTAsItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSupportedTAsItemMethodMarshalAPERChangedValue(v *SupportedTAsItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSupportedTAsItemMethodMarshalAPERLegacy(v *SupportedTAsItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSupportedTAsItemMethodMarshalAPERNewValue(v *SupportedTAsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSupportedTAsItemMethodMarshalAPERPlanned(v *SupportedTAsItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSupportedTAsItemMethodMarshalAPERTo(v *SupportedTAsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSupportedTAsItemMethodUnmarshalAPERFrom(v *SupportedTAsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSupportedTAsItemMethodUnmarshalAPERLegacy(v *SupportedTAsItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSupportedTAsItemMethodUnmarshalAPERWithOptions(v *SupportedTAsItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSupportedTAsItemValueCodecFieldCapture(v *SupportedTAsItemValueCodec) *func(SupportedTAsItem, aper.DecodeState) (SupportedTAsItem, aper.Snapshot) {
	return &v.capture
}
func BridgeSupportedTAsItemValueCodecFieldCompare(v *SupportedTAsItemValueCodec) *func(SupportedTAsItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSupportedTAsItemValueCodecFieldContext(v *SupportedTAsItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsItemValueCodecFieldDecode(v *SupportedTAsItemValueCodec) *func([]byte, aper.DecodeState) (SupportedTAsItem, error) {
	return &v.decode
}
func BridgeSupportedTAsItemValueCodecFieldEncode(v *SupportedTAsItemValueCodec) *func(SupportedTAsItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSupportedTAsItemValueCodecFieldPath(v *SupportedTAsItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeSupportedTAsItemValueCodecMethodEncodeBudgetValue(v SupportedTAsItemValueCodec, a0 SupportedTAsItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSupportedTAsItemValueCodecMethodEncodeChanged(v SupportedTAsItemValueCodec, a0 SupportedTAsItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSupportedTAsValueCodecFieldCapture(v *SupportedTAsValueCodec) *func(SupportedTAs, aper.DecodeState) (SupportedTAs, aper.Snapshot) {
	return &v.capture
}
func BridgeSupportedTAsValueCodecFieldCompare(v *SupportedTAsValueCodec) *func(SupportedTAs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSupportedTAsValueCodecFieldContext(v *SupportedTAsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsValueCodecFieldDecode(v *SupportedTAsValueCodec) *func([]byte, aper.DecodeState) (SupportedTAs, error) {
	return &v.decode
}
func BridgeSupportedTAsValueCodecFieldEncode(v *SupportedTAsValueCodec) *func(SupportedTAs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSupportedTAsValueCodecFieldPath(v *SupportedTAsValueCodec) *aper.Path { return &v.path }
func BridgeSupportedTAsValueCodecMethodEncodeBudgetValue(v SupportedTAsValueCodec, a0 SupportedTAs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSupportedTAsValueCodecMethodEncodeChanged(v SupportedTAsValueCodec, a0 SupportedTAs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSynchronisationInformationAPERValueFieldContext(v *SynchronisationInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSynchronisationInformationAPERValueFieldReceived(v *SynchronisationInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSynchronisationInformationAPERValueFieldReplay(v *SynchronisationInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSynchronisationInformationAPERValueFieldWithoutReplay(v *SynchronisationInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSynchronisationInformationFieldAggressoreCGIListIndef(v *SynchronisationInformation) *bool {
	return &v.aggressoreCGIListIndef
}
func BridgeSynchronisationInformationFieldExtCount(v *SynchronisationInformation) *int64 {
	return &v.extCount
}
func BridgeSynchronisationInformationFieldExtData(v *SynchronisationInformation) *[][]byte {
	return &v.extData
}
func BridgeSynchronisationInformationFieldExtOrigin(v *SynchronisationInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSynchronisationInformationFieldExtPresent(v *SynchronisationInformation) *[]bool {
	return &v.extPresent
}
func BridgeSynchronisationInformationFieldExtWire(v *SynchronisationInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSynchronisationInformationFieldIEExtensionsIndef(v *SynchronisationInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSynchronisationInformationFieldPerExtPadding(v *SynchronisationInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSynchronisationInformationFieldPerPadding(v *SynchronisationInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSynchronisationInformationFieldReceived(v *SynchronisationInformation) *bool {
	return &v.received
}
func BridgeSynchronisationInformationFieldReceivedAbsolute(v *SynchronisationInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeSynchronisationInformationFieldReceivedBytes(v *SynchronisationInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSynchronisationInformationFieldReceivedLocation(v *SynchronisationInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeSynchronisationInformationFieldReplay(v *SynchronisationInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeSynchronisationInformationFieldStream(v *SynchronisationInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeSynchronisationInformationFieldWithoutReplay(v *SynchronisationInformation) *bool {
	return &v.withoutReplay
}
func BridgeSynchronisationInformationMethodMarshalAPERBudget(v *SynchronisationInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSynchronisationInformationMethodMarshalAPERBudgetValue(v *SynchronisationInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSynchronisationInformationMethodMarshalAPERChanged(v *SynchronisationInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSynchronisationInformationMethodMarshalAPERChangedValue(v *SynchronisationInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSynchronisationInformationMethodMarshalAPERLegacy(v *SynchronisationInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSynchronisationInformationMethodMarshalAPERNewValue(v *SynchronisationInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSynchronisationInformationMethodMarshalAPERPlanned(v *SynchronisationInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSynchronisationInformationMethodMarshalAPERTo(v *SynchronisationInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSynchronisationInformationMethodUnmarshalAPERFrom(v *SynchronisationInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSynchronisationInformationMethodUnmarshalAPERLegacy(v *SynchronisationInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSynchronisationInformationMethodUnmarshalAPERWithOptions(v *SynchronisationInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSynchronisationInformationValueCodecFieldCapture(v *SynchronisationInformationValueCodec) *func(SynchronisationInformation, aper.DecodeState) (SynchronisationInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeSynchronisationInformationValueCodecFieldCompare(v *SynchronisationInformationValueCodec) *func(SynchronisationInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSynchronisationInformationValueCodecFieldContext(v *SynchronisationInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSynchronisationInformationValueCodecFieldDecode(v *SynchronisationInformationValueCodec) *func([]byte, aper.DecodeState) (SynchronisationInformation, error) {
	return &v.decode
}
func BridgeSynchronisationInformationValueCodecFieldEncode(v *SynchronisationInformationValueCodec) *func(SynchronisationInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSynchronisationInformationValueCodecFieldPath(v *SynchronisationInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSynchronisationInformationValueCodecMethodEncodeBudgetValue(v SynchronisationInformationValueCodec, a0 SynchronisationInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSynchronisationInformationValueCodecMethodEncodeChanged(v SynchronisationInformationValueCodec, a0 SynchronisationInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldCodec(v *UEInformationTransferERABLevelQoSParametersIEBinding) *s18.ERABLevelQoSParametersValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldGet(v *UEInformationTransferERABLevelQoSParametersIEBinding) *func(*UEInformationTransferIEValue) (*s18.ERABLevelQoSParameters, bool) {
	return &v.get
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldInfo(v *UEInformationTransferERABLevelQoSParametersIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldInject(v *UEInformationTransferERABLevelQoSParametersIEBinding) *func(s18.ERABLevelQoSParameters) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferIEContainerAPERValueFieldContext(v *UEInformationTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEContainerAPERValueFieldReceived(v *UEInformationTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEContainerAPERValueFieldReplay(v *UEInformationTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEContainerAPERValueFieldWithoutReplay(v *UEInformationTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEContainerValueCodecFieldCapture(v *UEInformationTransferIEContainerValueCodec) *func(UEInformationTransferIEContainer, aper.DecodeState) (UEInformationTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEContainerValueCodecFieldCompare(v *UEInformationTransferIEContainerValueCodec) *func(UEInformationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEContainerValueCodecFieldContext(v *UEInformationTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEContainerValueCodecFieldDecode(v *UEInformationTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEContainer, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEContainerValueCodecFieldEncode(v *UEInformationTransferIEContainerValueCodec) *func(UEInformationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEContainerValueCodecFieldPath(v *UEInformationTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEContainerValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEContainerValueCodec, a0 UEInformationTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEContainerValueCodecMethodEncodeChanged(v UEInformationTransferIEContainerValueCodec, a0 UEInformationTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferIEFieldAPERValueFieldContext(v *UEInformationTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEFieldAPERValueFieldReceived(v *UEInformationTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEFieldAPERValueFieldReplay(v *UEInformationTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEFieldAPERValueFieldWithoutReplay(v *UEInformationTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEFieldFieldReceived(v *UEInformationTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEInformationTransferIEFieldFieldReplay(v *UEInformationTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEFieldFieldStream(v *UEInformationTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEInformationTransferIEFieldFieldWithoutReplay(v *UEInformationTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEFieldMethodMarshalAPERTo(v *UEInformationTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(v *UEInformationTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEInformationTransferIEFieldValueCodecFieldCapture(v *UEInformationTransferIEFieldValueCodec) *func(UEInformationTransferIEField, aper.DecodeState) (UEInformationTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEFieldValueCodecFieldCompare(v *UEInformationTransferIEFieldValueCodec) *func(UEInformationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEFieldValueCodecFieldContext(v *UEInformationTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEFieldValueCodecFieldDecode(v *UEInformationTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEField, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEFieldValueCodecFieldEncode(v *UEInformationTransferIEFieldValueCodec) *func(UEInformationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEFieldValueCodecFieldPath(v *UEInformationTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEFieldValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEFieldValueCodec, a0 UEInformationTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEFieldValueCodecMethodEncodeChanged(v UEInformationTransferIEFieldValueCodec, a0 UEInformationTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferIETableMethodInfoMaskedIMEISV(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoMaskedIMEISV()
}
func BridgeUEInformationTransferIETableMethodInfoPendingDataIndication(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoPendingDataIndication()
}
func BridgeUEInformationTransferIETableMethodInfoSTMSI(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoSTMSI()
}
func BridgeUEInformationTransferIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgeUEInformationTransferIETableMethodInfoUELevelQoSParameters(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoUELevelQoSParameters()
}
func BridgeUEInformationTransferIETableMethodInfoUERadioCapability(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoUERadioCapability()
}
func BridgeUEInformationTransferIEValueERABIEContainerListAPERValueFieldContext(v *UEInformationTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueERABIEContainerListAPERValueFieldReceived(v *UEInformationTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEValueERABIEContainerListAPERValueFieldReplay(v *UEInformationTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEInformationTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *func(UEInformationTransferIEValueERABIEContainerList, aper.DecodeState) (UEInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *func(UEInformationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldContext(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *func(UEInformationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldPath(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEValueERABIEContainerListValueCodec, a0 UEInformationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEInformationTransferIEValueERABIEContainerListValueCodec, a0 UEInformationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferIEValueFieldId(v *UEInformationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEInformationTransferIEValueFieldIsOpaque(v *UEInformationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEInformationTransferIEValueFieldOpaque(v *UEInformationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEInformationTransferIEValueFieldReceived(v *UEInformationTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEValueFieldReplay(v *UEInformationTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEValueFieldRowMaskedIMEISV(v *UEInformationTransferIEValue) **s00.MaskedIMEISV {
	return &v.rowMaskedIMEISV
}
func BridgeUEInformationTransferIEValueFieldRowPendingDataIndication(v *UEInformationTransferIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgeUEInformationTransferIEValueFieldRowSTMSI(v *UEInformationTransferIEValue) **s28.STMSI {
	return &v.rowSTMSI
}
func BridgeUEInformationTransferIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *UEInformationTransferIEValue) **SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgeUEInformationTransferIEValueFieldRowUELevelQoSParameters(v *UEInformationTransferIEValue) **s18.ERABLevelQoSParameters {
	return &v.rowUELevelQoSParameters
}
func BridgeUEInformationTransferIEValueFieldRowUERadioCapability(v *UEInformationTransferIEValue) **s00.UERadioCapability {
	return &v.rowUERadioCapability
}
func BridgeUEInformationTransferIEValueMethodCaptureSemantics(v UEInformationTransferIEValue, a0 aper.SemanticCapture) UEInformationTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEInformationTransferIEValueMethodCompareSemantics(v UEInformationTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEInformationTransferIEValueMethodDecode(v UEInformationTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEInformationTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEInformationTransferIEValueMethodEncode(v UEInformationTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEInformationTransferIEValueMethodEncodeFresh(v UEInformationTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEInformationTransferIEValueMethodMatchesID(v UEInformationTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEInformationTransferIEValueMethodReason(v UEInformationTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEInformationTransferIEValueMethodRule(v UEInformationTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 UEInformationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 UEInformationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *UEInformationTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEInformationTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEInformationTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEInformationTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolIEContainerList, aper.DecodeState) (UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEValueProtocolIEContainerListValueCodec, a0 UEInformationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEInformationTransferIEValueProtocolIEContainerListValueCodec, a0 UEInformationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferMaskedIMEISVIEBindingFieldCodec(v *UEInformationTransferMaskedIMEISVIEBinding) *s01.MaskedIMEISVValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferMaskedIMEISVIEBindingFieldGet(v *UEInformationTransferMaskedIMEISVIEBinding) *func(*UEInformationTransferIEValue) (*s00.MaskedIMEISV, bool) {
	return &v.get
}
func BridgeUEInformationTransferMaskedIMEISVIEBindingFieldInfo(v *UEInformationTransferMaskedIMEISVIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferMaskedIMEISVIEBindingFieldInject(v *UEInformationTransferMaskedIMEISVIEBinding) *func(s00.MaskedIMEISV) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferPendingDataIndicationIEBindingFieldCodec(v *UEInformationTransferPendingDataIndicationIEBinding) *s01.PendingDataIndicationValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferPendingDataIndicationIEBindingFieldGet(v *UEInformationTransferPendingDataIndicationIEBinding) *func(*UEInformationTransferIEValue) (*s00.PendingDataIndication, bool) {
	return &v.get
}
func BridgeUEInformationTransferPendingDataIndicationIEBindingFieldInfo(v *UEInformationTransferPendingDataIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferPendingDataIndicationIEBindingFieldInject(v *UEInformationTransferPendingDataIndicationIEBinding) *func(s00.PendingDataIndication) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferSTMSIIEBindingFieldCodec(v *UEInformationTransferSTMSIIEBinding) *s28.STMSIValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferSTMSIIEBindingFieldGet(v *UEInformationTransferSTMSIIEBinding) *func(*UEInformationTransferIEValue) (*s28.STMSI, bool) {
	return &v.get
}
func BridgeUEInformationTransferSTMSIIEBindingFieldInfo(v *UEInformationTransferSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferSTMSIIEBindingFieldInject(v *UEInformationTransferSTMSIIEBinding) *func(s28.STMSI) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(v *UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) *SubscriptionBasedUEDifferentiationInfoValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(v *UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) *func(*UEInformationTransferIEValue) (*SubscriptionBasedUEDifferentiationInfo, bool) {
	return &v.get
}
func BridgeUEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(v *UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(v *UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) *func(SubscriptionBasedUEDifferentiationInfo) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferUERadioCapabilityIEBindingFieldCodec(v *UEInformationTransferUERadioCapabilityIEBinding) *s02.UERadioCapabilityValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferUERadioCapabilityIEBindingFieldGet(v *UEInformationTransferUERadioCapabilityIEBinding) *func(*UEInformationTransferIEValue) (*s00.UERadioCapability, bool) {
	return &v.get
}
func BridgeUEInformationTransferUERadioCapabilityIEBindingFieldInfo(v *UEInformationTransferUERadioCapabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferUERadioCapabilityIEBindingFieldInject(v *UEInformationTransferUERadioCapabilityIEBinding) *func(s00.UERadioCapability) UEInformationTransferIEValue {
	return &v.inject
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ConnectionEstablishmentIndicationIEValue) Selected() (any, bool) {
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
	case 74:
		if value, ok := v.AsUERadioCapability(); ok {
			return value, true
		}
	case 251:
		if value, ok := v.AsEnhancedCoverageRestricted(); ok {
			return value, true
		}
	case 253:
		if value, ok := v.AsDLCPSecurityInformation(); ok {
			return value, true
		}
	case 271:
		if value, ok := v.AsCEModeBRestricted(); ok {
			return value, true
		}
	case 280:
		if value, ok := v.AsEndIndication(); ok {
			return value, true
		}
	case 278:
		if value, ok := v.AsSubscriptionBasedUEDifferentiationInfo(); ok {
			return value, true
		}
	case 252:
		if value, ok := v.AsUELevelQoSParameters(); ok {
			return value, true
		}
	case 314:
		if value, ok := v.AsUERadioCapabilityID(); ok {
			return value, true
		}
	case 192:
		if value, ok := v.AsMaskedIMEISV(); ok {
			return value, true
		}
	case 354:
		if value, ok := v.AsCoarseUELocation(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UEInformationTransferIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 96:
		if value, ok := v.AsSTMSI(); ok {
			return value, true
		}
	case 252:
		if value, ok := v.AsUELevelQoSParameters(); ok {
			return value, true
		}
	case 74:
		if value, ok := v.AsUERadioCapability(); ok {
			return value, true
		}
	case 278:
		if value, ok := v.AsSubscriptionBasedUEDifferentiationInfo(); ok {
			return value, true
		}
	case 283:
		if value, ok := v.AsPendingDataIndication(); ok {
			return value, true
		}
	case 192:
		if value, ok := v.AsMaskedIMEISV(); ok {
			return value, true
		}
	}
	return nil, false
}
