// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s39 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s39

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
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
func BridgeERABSecurityResultListIEValueCaptureS1APProtocolIESingleContainer(v *s38.ERABSecurityResultListIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSecurityResultListIEValueCompareS1APProtocolIESingleContainer(v *s38.ERABSecurityResultListIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSecurityResultListIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.SensorMeasConfigNameItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.SensorMeasConfigNameItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.SensorMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.SensorMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIESingleContainer(v *s13.SensorNameConfigExtIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(v *s13.SensorNameConfigExtIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.ServedDCNsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.ServedDCNsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.ServedGUMMEIsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.ServedGUMMEIsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.SourceNgRanNodeIDExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.SourceNgRanNodeIDExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.SourceeNBIDExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.SourceeNBIDExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// ERABSecurityResultListValueCodec is the concrete ValueCodec[ERABSecurityResultList].
type ERABSecurityResultListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s38.ERABSecurityResultList,

		error)
	encode func(s38.ERABSecurityResultList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s38.ERABSecurityResultList, aper.DecodeState,

	) (s38.ERABSecurityResultList, aper.Snapshot,

	)
	compare func(s38.ERABSecurityResultList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultListValueCodec) New(value s38.ERABSecurityResultList,

) (s38.ERABSecurityResultListAPERValue, error) {
	if c.encode == nil {
		return s38.ERABSecurityResultListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s38.ERABSecurityResultListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s38.ERABSecurityResultListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s38.ERABSecurityResultListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s38.ERABSecurityResultListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s38.ERABSecurityResultListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s38.ERABSecurityResultListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s38.ERABSecurityResultListAPERValue {
			sealed := s38.ERABSecurityResultListAPERValue{Value: value}
			*s38.BridgeERABSecurityResultListAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s38.BridgeERABSecurityResultListAPERValueFieldReplay(&sealed) = replay
			*s38.BridgeERABSecurityResultListAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s38.ERABSecurityResultListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultListValueCodec) EncodeAPER(value s38.ERABSecurityResultListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s38.BridgeERABSecurityResultListAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s38.BridgeERABSecurityResultListAPERValueFieldContext(&value) == c.context && !fresh && (*s38.BridgeERABSecurityResultListAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s38.BridgeERABSecurityResultListAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s38.BridgeERABSecurityResultListAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s38.BridgeERABSecurityResultListAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSecurityResultListValueCodec) encodeBudgetValue(value s38.ERABSecurityResultList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultListValueCodec) encodeChanged(value s38.ERABSecurityResultList,

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
	codec  s17.DLCPSecurityInformationValueCodec
	inject func(s17.DLCPSecurityInformation,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s17.DLCPSecurityInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) Codec() s17.DLCPSecurityInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) New(value s17.DLCPSecurityInformation,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeDLCPSecurityInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s17.DLCPSecurityInformation,

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
	codec  s21.ERABLevelQoSParametersValueCodec
	inject func(s21.ERABLevelQoSParameters,

	) ConnectionEstablishmentIndicationIEValue

	get func(*ConnectionEstablishmentIndicationIEValue,

	) (*s21.ERABLevelQoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) Codec() s21.ERABLevelQoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) New(value s21.ERABLevelQoSParameters,

) (ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s21.BridgeERABLevelQoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding) Get(field *ConnectionEstablishmentIndicationIEField) (*s21.ERABLevelQoSParameters,

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
	codec  s36.STMSIValueCodec
	inject func(s36.STMSI,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s36.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferSTMSIIEBinding) Codec() s36.STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEInformationTransferSTMSIIEBinding) New(value s36.STMSI,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s36.BridgeSTMSIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferSTMSIIEBinding) Get(field *UEInformationTransferIEField) (*s36.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferERABLevelQoSParametersIEBinding binds ERABLevelQoSParameters to the UEInformationTransferIEs object set of TS 36.413.
type UEInformationTransferERABLevelQoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s21.ERABLevelQoSParametersValueCodec
	inject func(s21.ERABLevelQoSParameters,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s21.ERABLevelQoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Codec() s21.ERABLevelQoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) New(value s21.ERABLevelQoSParameters,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s21.BridgeERABLevelQoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Get(field *UEInformationTransferIEField) (*s21.ERABLevelQoSParameters,

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

// SecurityResultValueCodec is the concrete ValueCodec[SecurityResult].
type SecurityResultValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s38.SecurityResult,

		error)
	encode func(s38.SecurityResult,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s38.SecurityResult, aper.DecodeState,

	) (s38.SecurityResult, aper.Snapshot,

	)
	compare func(s38.SecurityResult, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityResultValueCodec) New(value s38.SecurityResult,

) (SecurityResultAPERValue, error) {
	if c.encode == nil {
		return SecurityResultAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityResultAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityResultAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityResultAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityResultValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityResultAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityResultAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityResultAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityResultAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityResultAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityResultValueCodec) EncodeAPER(value SecurityResultAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecurityResultValueCodec) encodeBudgetValue(value s38.SecurityResult,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityResultValueCodec) encodeChanged(value s38.SecurityResult,

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
	decode  func([]byte, aper.DecodeState) (SensorNameConfig,

		error)
	encode func(SensorNameConfig,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorNameConfig, aper.DecodeState,

	) (SensorNameConfig, aper.Snapshot,

	)
	compare func(SensorNameConfig, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorNameConfigValueCodec) New(value SensorNameConfig,

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
func (c SensorNameConfigValueCodec) encodeBudgetValue(value SensorNameConfig,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorNameConfigValueCodec) encodeChanged(value SensorNameConfig,

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

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABSecurityResultListIEValueValidateS1APIEContainer(fields s38.ERABSecurityResultListIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s38.BridgeERABSecurityResultListIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s38.BridgeERABSecurityResultListIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s38.BridgeERABSecurityResultListIEValueMethodRule(field.Value).Assignment
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
func BridgeSecurityResultExtIEsValueValidateS1APExtensionContainer(fields s13.SecurityResultExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.SecurityResultExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.SecurityResultExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSecurityResultExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APExtensionContainer(fields s13.SensorMeasConfigNameItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.SensorMeasConfigNameItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.SensorMeasConfigNameItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields s13.SensorMeasurementConfigurationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.SensorMeasurementConfigurationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.SensorMeasurementConfigurationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeServedDCNsItemExtIEsValueValidateS1APExtensionContainer(fields s13.ServedDCNsItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.ServedDCNsItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.ServedDCNsItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeServedDCNsItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeServedGUMMEIsItemExtIEsValueValidateS1APExtensionContainer(fields s13.ServedGUMMEIsItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.ServedGUMMEIsItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.ServedGUMMEIsItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeServedGUMMEIsItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSourceNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields s13.SourceNgRanNodeIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.SourceNgRanNodeIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.SourceNgRanNodeIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSourceNgRanNodeIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSourceeNBIDExtIEsValueValidateS1APExtensionContainer(fields s13.SourceeNBIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.SourceeNBIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.SourceeNBIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSourceeNBIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ERABSecurityResultListIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABSecurityResultListIEs}} codec of TS 36.413.
func ERABSecurityResultListIEValueERABIEContainerListCodec(table s00.ERABSecurityResultListIEValueIETable) s38.ERABSecurityResultListIEValueERABIEContainerListValueCodec {
	codec := ERABSecurityResultListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s38.BridgeERABSecurityResultListIEContainerValueCodecFieldDecode(&codec) == nil {
		return s38.ERABSecurityResultListIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s38.ERABSecurityResultListIEValueERABIEContainerListValueCodec {
		sealed := s38.ERABSecurityResultListIEValueERABIEContainerListValueCodec{}
		*s38.BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABSecurityResultListIEValueERABIEContainerList"
		*s38.BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.ERABSecurityResultListIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s38.ERABSecurityResultListIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s38.ERABSecurityResultListIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s38.BridgeERABSecurityResultListIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSecurityResultListIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSecurityResultListIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSecurityResultListIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s38.BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s38.ERABSecurityResultListIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldEncode(&codec))(s38.ERABSecurityResultListIEContainer(value), fresh, budget)
		}
		*s38.BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s38.ERABSecurityResultListIEValueERABIEContainerList, options aper.DecodeState) (s38.ERABSecurityResultListIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s38.BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s38.ERABSecurityResultListIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s38.BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SensorNameConfigExtIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{SensorNameConfig-ExtIEs}} codec of TS 36.413.
func SensorNameConfigExtIEValueERABIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable) s13.SensorNameConfigExtIEValueERABIEContainerListValueCodec {
	codec := SensorNameConfigExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s13.SensorNameConfigExtIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s13.SensorNameConfigExtIEValueERABIEContainerListValueCodec {
		sealed := s13.SensorNameConfigExtIEValueERABIEContainerListValueCodec{}
		*s13.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "SensorNameConfigExtIEValueERABIEContainerList"
		*s13.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorNameConfigExtIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SensorNameConfigExtIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SensorNameConfigExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s13.SensorNameConfigExtIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s13.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s13.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s13.SensorNameConfigExtIEValueERABIEContainerList, options aper.DecodeState) (s13.SensorNameConfigExtIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s13.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s13.SensorNameConfigExtIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceNodeIDExtensionIEIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{SourceNodeID-ExtensionIE}} codec of TS 36.413.
func SourceNodeIDExtensionIEIEValueERABIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable) s13.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s13.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s13.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec {
		sealed := s13.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec{}
		*s13.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "SourceNodeIDExtensionIEIEValueERABIEContainerList"
		*s13.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SourceNodeIDExtensionIEIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SourceNodeIDExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s13.SourceNodeIDExtensionIEIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&codec))(s13.SourceNodeIDExtensionIEIEContainer(value), fresh, budget)
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s13.SourceNodeIDExtensionIEIEValueERABIEContainerList, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s13.SourceNodeIDExtensionIEIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SensorMeasConfigNameItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SensorMeasConfigNameItem-ExtIEs}} codec of TS 36.413.
func SensorMeasConfigNameItemExtIEsValueExtensionFieldTableCodec(table s00.SensorMeasConfigNameItemExtIEsValueExtensionTable) s13.SensorMeasConfigNameItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeSensorMeasConfigNameItemExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SensorMeasConfigNameItemExtIEsExtFieldValueCodec{}
	}
	return func() s13.SensorMeasConfigNameItemExtIEsExtFieldValueCodec {
		sealed := s13.SensorMeasConfigNameItemExtIEsExtFieldValueCodec{}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "SensorMeasConfigNameItemExtIEsExtField"
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorMeasConfigNameItemExtIEsExtField, error) {
			var field s13.SensorMeasConfigNameItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SensorMeasConfigNameItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorMeasConfigNameItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SensorMeasConfigNameItemExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.SensorMeasConfigNameItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.SensorMeasConfigNameItemExtIEsExtField, options aper.DecodeState) (s13.SensorMeasConfigNameItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.SensorMeasConfigNameItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SensorMeasurementConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SensorMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func SensorMeasurementConfigurationExtIEsValueExtensionFieldTableCodec(table s00.SensorMeasurementConfigurationExtIEsValueExtensionTable) s13.SensorMeasurementConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeSensorMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SensorMeasurementConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s13.SensorMeasurementConfigurationExtIEsExtFieldValueCodec {
		sealed := s13.SensorMeasurementConfigurationExtIEsExtFieldValueCodec{}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "SensorMeasurementConfigurationExtIEsExtField"
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorMeasurementConfigurationExtIEsExtField, error) {
			var field s13.SensorMeasurementConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SensorMeasurementConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorMeasurementConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SensorMeasurementConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.SensorMeasurementConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.SensorMeasurementConfigurationExtIEsExtField, options aper.DecodeState) (s13.SensorMeasurementConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.SensorMeasurementConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedDCNsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ServedDCNsItem-ExtIEs}} codec of TS 36.413.
func ServedDCNsItemExtIEsValueExtensionFieldTableCodec(table s00.ServedDCNsItemExtIEsValueExtensionTable) s13.ServedDCNsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeServedDCNsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s13.ServedDCNsItemExtIEsExtFieldValueCodec{}
	}
	return func() s13.ServedDCNsItemExtIEsExtFieldValueCodec {
		sealed := s13.ServedDCNsItemExtIEsExtFieldValueCodec{}
		*s13.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ServedDCNsItemExtIEsExtField"
		*s13.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.ServedDCNsItemExtIEsExtField, error) {
			var field s13.ServedDCNsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ServedDCNsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ServedDCNsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ServedDCNsItemExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.ServedDCNsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeServedDCNsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.ServedDCNsItemExtIEsExtField, options aper.DecodeState) (s13.ServedDCNsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.ServedDCNsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedGUMMEIsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ServedGUMMEIsItem-ExtIEs}} codec of TS 36.413.
func ServedGUMMEIsItemExtIEsValueExtensionFieldTableCodec(table s00.ServedGUMMEIsItemExtIEsValueExtensionTable) s13.ServedGUMMEIsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeServedGUMMEIsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s13.ServedGUMMEIsItemExtIEsExtFieldValueCodec{}
	}
	return func() s13.ServedGUMMEIsItemExtIEsExtFieldValueCodec {
		sealed := s13.ServedGUMMEIsItemExtIEsExtFieldValueCodec{}
		*s13.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ServedGUMMEIsItemExtIEsExtField"
		*s13.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.ServedGUMMEIsItemExtIEsExtField, error) {
			var field s13.ServedGUMMEIsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ServedGUMMEIsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ServedGUMMEIsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ServedGUMMEIsItemExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.ServedGUMMEIsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeServedGUMMEIsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.ServedGUMMEIsItemExtIEsExtField, options aper.DecodeState) (s13.ServedGUMMEIsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.ServedGUMMEIsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceNgRanNodeIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SourceNgRanNode-ID-ExtIEs}} codec of TS 36.413.
func SourceNgRanNodeIDExtIEsValueExtensionFieldTableCodec(table s00.SourceNgRanNodeIDExtIEsValueExtensionTable) s13.SourceNgRanNodeIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeSourceNgRanNodeIDExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SourceNgRanNodeIDExtIEsExtFieldValueCodec{}
	}
	return func() s13.SourceNgRanNodeIDExtIEsExtFieldValueCodec {
		sealed := s13.SourceNgRanNodeIDExtIEsExtFieldValueCodec{}
		*s13.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldPath(&sealed) = "SourceNgRanNodeIDExtIEsExtField"
		*s13.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceNgRanNodeIDExtIEsExtField, error) {
			var field s13.SourceNgRanNodeIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceNgRanNodeIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNgRanNodeIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceNgRanNodeIDExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.SourceNgRanNodeIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.SourceNgRanNodeIDExtIEsExtField, options aper.DecodeState) (s13.SourceNgRanNodeIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.SourceNgRanNodeIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceeNBIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SourceeNB-ID-ExtIEs}} codec of TS 36.413.
func SourceeNBIDExtIEsValueExtensionFieldTableCodec(table s00.SourceeNBIDExtIEsValueExtensionTable) s13.SourceeNBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeSourceeNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SourceeNBIDExtIEsExtFieldValueCodec{}
	}
	return func() s13.SourceeNBIDExtIEsExtFieldValueCodec {
		sealed := s13.SourceeNBIDExtIEsExtFieldValueCodec{}
		*s13.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldPath(&sealed) = "SourceeNBIDExtIEsExtField"
		*s13.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceeNBIDExtIEsExtField, error) {
			var field s13.SourceeNBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeSourceeNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceeNBIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceeNBIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceeNBIDExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.SourceeNBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeSourceeNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.SourceeNBIDExtIEsExtField, options aper.DecodeState) (s13.SourceeNBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.SourceeNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Subscription-Based-UE-DifferentiationInfo-ExtIEs}} codec of TS 36.413.
func SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionFieldTableCodec(table s00.SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTable) s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec{}
	}
	return func() s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec {
		sealed := s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec{}
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldPath(&sealed) = "SubscriptionBasedUEDifferentiationInfoExtIEsExtField"
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, error) {
			var field s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SubscriptionBasedUEDifferentiationInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfoExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, options aper.DecodeState) (s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SecurityResultExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SecurityResult-ExtIEs}} codec of TS 36.413.
func SecurityResultExtIEsValueExtensionTableCodec(table s00.SecurityResultExtIEsValueExtensionTable, bounds aper.ListBounds) s13.SecurityResultExtIEsExtContainerValueCodec {
	if !*s00.BridgeSecurityResultExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SecurityResultExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SecurityResultExtIEsExtContainerValueCodec {
		sealed := s13.SecurityResultExtIEsExtContainerValueCodec{}
		*s13.BridgeSecurityResultExtIEsExtContainerValueCodecFieldPath(&sealed) = "SecurityResultExtIEsExtContainer"
		*s13.BridgeSecurityResultExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SecurityResultExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SecurityResultExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SecurityResultExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSecurityResultExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SecurityResultExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SecurityResultExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SecurityResultExtIEsExtContainer")
			}
			return fields, nil
		}
		*s13.BridgeSecurityResultExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.SecurityResultExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSecurityResultExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSecurityResultExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.SecurityResultExtIEsExtContainer, options aper.DecodeState) (s13.SecurityResultExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s38.BridgeSecurityResultExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSecurityResultExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.SecurityResultExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s38.BridgeSecurityResultExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSecurityResultExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SensorMeasConfigNameItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SensorMeasConfigNameItem-ExtIEs}} codec of TS 36.413.
func SensorMeasConfigNameItemExtIEsValueExtensionTableCodec(table s00.SensorMeasConfigNameItemExtIEsValueExtensionTable, bounds aper.ListBounds) s13.SensorMeasConfigNameItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeSensorMeasConfigNameItemExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SensorMeasConfigNameItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SensorMeasConfigNameItemExtIEsExtContainerValueCodec {
		sealed := s13.SensorMeasConfigNameItemExtIEsExtContainerValueCodec{}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "SensorMeasConfigNameItemExtIEsExtContainer"
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorMeasConfigNameItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SensorMeasConfigNameItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SensorMeasConfigNameItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SensorMeasConfigNameItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorMeasConfigNameItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SensorMeasConfigNameItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.SensorMeasConfigNameItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.SensorMeasConfigNameItemExtIEsExtContainer, options aper.DecodeState) (s13.SensorMeasConfigNameItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.SensorMeasConfigNameItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SensorMeasurementConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SensorMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func SensorMeasurementConfigurationExtIEsValueExtensionTableCodec(table s00.SensorMeasurementConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s13.SensorMeasurementConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeSensorMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SensorMeasurementConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SensorMeasurementConfigurationExtIEsExtContainerValueCodec {
		sealed := s13.SensorMeasurementConfigurationExtIEsExtContainerValueCodec{}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldPath(&sealed) = "SensorMeasurementConfigurationExtIEsExtContainer"
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorMeasurementConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SensorMeasurementConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SensorMeasurementConfigurationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SensorMeasurementConfigurationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorMeasurementConfigurationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SensorMeasurementConfigurationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.SensorMeasurementConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.SensorMeasurementConfigurationExtIEsExtContainer, options aper.DecodeState) (s13.SensorMeasurementConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.SensorMeasurementConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ServedDCNsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ServedDCNsItem-ExtIEs}} codec of TS 36.413.
func ServedDCNsItemExtIEsValueExtensionTableCodec(table s00.ServedDCNsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s13.ServedDCNsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeServedDCNsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s13.ServedDCNsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.ServedDCNsItemExtIEsExtContainerValueCodec {
		sealed := s13.ServedDCNsItemExtIEsExtContainerValueCodec{}
		*s13.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ServedDCNsItemExtIEsExtContainer"
		*s13.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.ServedDCNsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.ServedDCNsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.ServedDCNsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.ServedDCNsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeServedDCNsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.ServedDCNsItemExtIEsExtContainer, options aper.DecodeState) (s13.ServedDCNsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.ServedDCNsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ServedGUMMEIsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ServedGUMMEIsItem-ExtIEs}} codec of TS 36.413.
func ServedGUMMEIsItemExtIEsValueExtensionTableCodec(table s00.ServedGUMMEIsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s13.ServedGUMMEIsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeServedGUMMEIsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s13.ServedGUMMEIsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.ServedGUMMEIsItemExtIEsExtContainerValueCodec {
		sealed := s13.ServedGUMMEIsItemExtIEsExtContainerValueCodec{}
		*s13.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ServedGUMMEIsItemExtIEsExtContainer"
		*s13.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.ServedGUMMEIsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.ServedGUMMEIsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.ServedGUMMEIsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.ServedGUMMEIsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeServedGUMMEIsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.ServedGUMMEIsItemExtIEsExtContainer, options aper.DecodeState) (s13.ServedGUMMEIsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.ServedGUMMEIsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SourceNgRanNodeIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SourceNgRanNode-ID-ExtIEs}} codec of TS 36.413.
func SourceNgRanNodeIDExtIEsValueExtensionTableCodec(table s00.SourceNgRanNodeIDExtIEsValueExtensionTable, bounds aper.ListBounds) s13.SourceNgRanNodeIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeSourceNgRanNodeIDExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SourceNgRanNodeIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SourceNgRanNodeIDExtIEsExtContainerValueCodec {
		sealed := s13.SourceNgRanNodeIDExtIEsExtContainerValueCodec{}
		*s13.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldPath(&sealed) = "SourceNgRanNodeIDExtIEsExtContainer"
		*s13.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceNgRanNodeIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SourceNgRanNodeIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SourceNgRanNodeIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.SourceNgRanNodeIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.SourceNgRanNodeIDExtIEsExtContainer, options aper.DecodeState) (s13.SourceNgRanNodeIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.SourceNgRanNodeIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SourceeNBIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SourceeNB-ID-ExtIEs}} codec of TS 36.413.
func SourceeNBIDExtIEsValueExtensionTableCodec(table s00.SourceeNBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s13.SourceeNBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeSourceeNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SourceeNBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SourceeNBIDExtIEsExtContainerValueCodec {
		sealed := s13.SourceeNBIDExtIEsExtContainerValueCodec{}
		*s13.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldPath(&sealed) = "SourceeNBIDExtIEsExtContainer"
		*s13.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceeNBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SourceeNBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SourceeNBIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSourceeNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.SourceeNBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSourceeNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.SourceeNBIDExtIEsExtContainer, options aper.DecodeState) (s13.SourceeNBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.SourceeNBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Subscription-Based-UE-DifferentiationInfo-ExtIEs}} codec of TS 36.413.
func SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableCodec(table s00.SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec {
		sealed := s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec{}
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldPath(&sealed) = "SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer"
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, options aper.DecodeState) (s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSecurityResultListIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABSecurityResultListIEs}} codec of TS 36.413.
func ERABSecurityResultListIEValueIEFieldTableCodec(table s00.ERABSecurityResultListIEValueIETable) s38.ERABSecurityResultListIEFieldValueCodec {
	if !*s00.BridgeERABSecurityResultListIEValueIETableFieldBound(&table) {
		return s38.ERABSecurityResultListIEFieldValueCodec{}
	}
	return func() s38.ERABSecurityResultListIEFieldValueCodec {
		sealed := s38.ERABSecurityResultListIEFieldValueCodec{}
		*s38.BridgeERABSecurityResultListIEFieldValueCodecFieldPath(&sealed) = "ERABSecurityResultListIEField"
		*s38.BridgeERABSecurityResultListIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.ERABSecurityResultListIEField, error) {
			var field s38.ERABSecurityResultListIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s38.BridgeERABSecurityResultListIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSecurityResultListIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSecurityResultListIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSecurityResultListIEField")
			}
			return field, nil
		}
		*s38.BridgeERABSecurityResultListIEFieldValueCodecFieldEncode(&sealed) = func(field s38.ERABSecurityResultListIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s38.BridgeERABSecurityResultListIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s38.BridgeERABSecurityResultListIEFieldValueCodecFieldCapture(&sealed) = func(v s38.ERABSecurityResultListIEField, options aper.DecodeState) (s38.ERABSecurityResultListIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s38.BridgeERABSecurityResultListIEFieldValueCodecFieldCompare(&sealed) = func(v s38.ERABSecurityResultListIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s38.BridgeERABSecurityResultListIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SensorNameConfigExtIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{SensorNameConfig-ExtIEs}} codec of TS 36.413.
func SensorNameConfigExtIEValueIEFieldTableCodec(table s00.SensorNameConfigExtIEValueIETable) s13.SensorNameConfigExtIEFieldValueCodec {
	if !*s00.BridgeSensorNameConfigExtIEValueIETableFieldBound(&table) {
		return s13.SensorNameConfigExtIEFieldValueCodec{}
	}
	return func() s13.SensorNameConfigExtIEFieldValueCodec {
		sealed := s13.SensorNameConfigExtIEFieldValueCodec{}
		*s13.BridgeSensorNameConfigExtIEFieldValueCodecFieldPath(&sealed) = "SensorNameConfigExtIEField"
		*s13.BridgeSensorNameConfigExtIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorNameConfigExtIEField, error) {
			var field s13.SensorNameConfigExtIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SensorNameConfigExtIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorNameConfigExtIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SensorNameConfigExtIEField")
			}
			return field, nil
		}
		*s13.BridgeSensorNameConfigExtIEFieldValueCodecFieldEncode(&sealed) = func(field s13.SensorNameConfigExtIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeSensorNameConfigExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeSensorNameConfigExtIEFieldValueCodecFieldCapture(&sealed) = func(v s13.SensorNameConfigExtIEField, options aper.DecodeState) (s13.SensorNameConfigExtIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSensorNameConfigExtIEFieldValueCodecFieldCompare(&sealed) = func(v s13.SensorNameConfigExtIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorNameConfigExtIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceNodeIDExtensionIEIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{SourceNodeID-ExtensionIE}} codec of TS 36.413.
func SourceNodeIDExtensionIEIEValueIEFieldTableCodec(table s00.SourceNodeIDExtensionIEIEValueIETable) s13.SourceNodeIDExtensionIEIEFieldValueCodec {
	if !*s00.BridgeSourceNodeIDExtensionIEIEValueIETableFieldBound(&table) {
		return s13.SourceNodeIDExtensionIEIEFieldValueCodec{}
	}
	return func() s13.SourceNodeIDExtensionIEIEFieldValueCodec {
		sealed := s13.SourceNodeIDExtensionIEIEFieldValueCodec{}
		*s13.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldPath(&sealed) = "SourceNodeIDExtensionIEIEField"
		*s13.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEField, error) {
			var field s13.SourceNodeIDExtensionIEIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNodeIDExtensionIEIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SourceNodeIDExtensionIEIEField")
			}
			return field, nil
		}
		*s13.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldEncode(&sealed) = func(field s13.SourceNodeIDExtensionIEIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeSourceNodeIDExtensionIEIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldCapture(&sealed) = func(v s13.SourceNodeIDExtensionIEIEField, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldCompare(&sealed) = func(v s13.SourceNodeIDExtensionIEIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSecurityResultListIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABSecurityResultListIEs}} codec of TS 36.413.
func ERABSecurityResultListIEValueIETableCodec(table s00.ERABSecurityResultListIEValueIETable, bounds aper.ListBounds) s38.ERABSecurityResultListIEContainerValueCodec {
	if !*s00.BridgeERABSecurityResultListIEValueIETableFieldBound(&table) {
		return s38.ERABSecurityResultListIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s38.ERABSecurityResultListIEContainerValueCodec {
		sealed := s38.ERABSecurityResultListIEContainerValueCodec{}
		*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldPath(&sealed) = "ERABSecurityResultListIEContainer"
		*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.ERABSecurityResultListIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s38.ERABSecurityResultListIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s38.ERABSecurityResultListIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s38.BridgeERABSecurityResultListIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSecurityResultListIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSecurityResultListIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSecurityResultListIEContainer")
			}
			return fields, nil
		}
		*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldEncode(&sealed) = func(fields s38.ERABSecurityResultListIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s38.BridgeERABSecurityResultListIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldCapture(&sealed) = func(v s38.ERABSecurityResultListIEContainer, options aper.DecodeState) (s38.ERABSecurityResultListIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldCompare(&sealed) = func(v s38.ERABSecurityResultListIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SensorNameConfigExtIEValueIETableCodec constructs the ProtocolIE-Container {{SensorNameConfig-ExtIEs}} codec of TS 36.413.
func SensorNameConfigExtIEValueIETableCodec(table s00.SensorNameConfigExtIEValueIETable, bounds aper.ListBounds) s13.SensorNameConfigExtIEContainerValueCodec {
	if !*s00.BridgeSensorNameConfigExtIEValueIETableFieldBound(&table) {
		return s13.SensorNameConfigExtIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SensorNameConfigExtIEContainerValueCodec {
		sealed := s13.SensorNameConfigExtIEContainerValueCodec{}
		*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldPath(&sealed) = "SensorNameConfigExtIEContainer"
		*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorNameConfigExtIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SensorNameConfigExtIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SensorNameConfigExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SensorNameConfigExtIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorNameConfigExtIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SensorNameConfigExtIEContainer")
			}
			return fields, nil
		}
		*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&sealed) = func(fields s13.SensorNameConfigExtIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSensorNameConfigExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldCapture(&sealed) = func(v s13.SensorNameConfigExtIEContainer, options aper.DecodeState) (s13.SensorNameConfigExtIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldCompare(&sealed) = func(v s13.SensorNameConfigExtIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SourceNodeIDExtensionIEIEValueIETableCodec constructs the ProtocolIE-Container {{SourceNodeID-ExtensionIE}} codec of TS 36.413.
func SourceNodeIDExtensionIEIEValueIETableCodec(table s00.SourceNodeIDExtensionIEIEValueIETable, bounds aper.ListBounds) s13.SourceNodeIDExtensionIEIEContainerValueCodec {
	if !*s00.BridgeSourceNodeIDExtensionIEIEValueIETableFieldBound(&table) {
		return s13.SourceNodeIDExtensionIEIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SourceNodeIDExtensionIEIEContainerValueCodec {
		sealed := s13.SourceNodeIDExtensionIEIEContainerValueCodec{}
		*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldPath(&sealed) = "SourceNodeIDExtensionIEIEContainer"
		*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SourceNodeIDExtensionIEIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SourceNodeIDExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&sealed) = func(fields s13.SourceNodeIDExtensionIEIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSourceNodeIDExtensionIEIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldCapture(&sealed) = func(v s13.SourceNodeIDExtensionIEIEContainer, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldCompare(&sealed) = func(v s13.SourceNodeIDExtensionIEIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSecurityResultListIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABSecurityResultListIEs}} codec of TS 36.413.
func ERABSecurityResultListIEValueProtocolErrorIEContainerListCodec(table s00.ERABSecurityResultListIEValueIETable) s38.ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSecurityResultListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s38.BridgeERABSecurityResultListIEContainerValueCodecFieldDecode(&codec) == nil {
		return s38.ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s38.ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s38.ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec{}
		*s38.BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABSecurityResultListIEValueProtocolErrorIEContainerList"
		*s38.BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.ERABSecurityResultListIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s38.ERABSecurityResultListIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s38.ERABSecurityResultListIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s38.BridgeERABSecurityResultListIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSecurityResultListIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSecurityResultListIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSecurityResultListIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s38.BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s38.ERABSecurityResultListIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldEncode(&codec))(s38.ERABSecurityResultListIEContainer(value), fresh, budget)
		}
		*s38.BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s38.ERABSecurityResultListIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s38.ERABSecurityResultListIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s38.BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s38.ERABSecurityResultListIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s38.BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SensorNameConfigExtIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{SensorNameConfig-ExtIEs}} codec of TS 36.413.
func SensorNameConfigExtIEValueProtocolErrorIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable) s13.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec {
	codec := SensorNameConfigExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s13.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s13.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s13.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec{}
		*s13.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "SensorNameConfigExtIEValueProtocolErrorIEContainerList"
		*s13.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorNameConfigExtIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SensorNameConfigExtIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SensorNameConfigExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s13.SensorNameConfigExtIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s13.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s13.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s13.SensorNameConfigExtIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s13.SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s13.SensorNameConfigExtIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{SourceNodeID-ExtensionIE}} codec of TS 36.413.
func SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable) s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList"
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SourceNodeIDExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&codec))(s13.SourceNodeIDExtensionIEIEContainer(value), fresh, budget)
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSecurityResultListIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABSecurityResultListIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABSecurityResultListIEValueProtocolIEContainerListCodec(table s00.ERABSecurityResultListIEValueIETable, bounds aper.ListBounds) ERABSecurityResultListIEValueProtocolIEContainerListValueCodec {
	codec := ERABSecurityResultListIEValueIETableCodec(table, bounds)
	if *s38.BridgeERABSecurityResultListIEContainerValueCodecFieldDecode(&codec) == nil {
		return ERABSecurityResultListIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ERABSecurityResultListIEValueProtocolIEContainerListValueCodec{path: "ERABSecurityResultListIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (s38.ERABSecurityResultListIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields s38.ERABSecurityResultListIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field s38.ERABSecurityResultListIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := s38.BridgeERABSecurityResultListIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
			return nil, runtime.WrapDecodePath(err, "ERABSecurityResultListIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABSecurityResultListIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABSecurityResultListIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value s38.ERABSecurityResultListIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (*s38.BridgeERABSecurityResultListIEContainerValueCodecFieldEncode(&codec))(s38.ERABSecurityResultListIEContainer(value), fresh, budget)
	}, capture: func(v s38.ERABSecurityResultListIEValueProtocolIEContainerList, options aper.DecodeState) (s38.ERABSecurityResultListIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v s38.ERABSecurityResultListIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeERABSecurityResultListIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func SensorNameConfigExtIEValueProtocolIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable, bounds aper.ListBounds) s13.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec {
	codec := SensorNameConfigExtIEValueIETableCodec(table, bounds)
	if *s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s13.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s13.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec {
		sealed := s13.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec{}
		*s13.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "SensorNameConfigExtIEValueProtocolIEContainerList"
		*s13.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SensorNameConfigExtIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SensorNameConfigExtIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SensorNameConfigExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s13.SensorNameConfigExtIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s13.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s13.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s13.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s13.SensorNameConfigExtIEValueProtocolIEContainerList, options aper.DecodeState) (s13.SensorNameConfigExtIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s13.SensorNameConfigExtIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SourceNodeIDExtensionIEIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {SourceNodeID-ExtensionIE} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func SourceNodeIDExtensionIEIEValueProtocolIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable, bounds aper.ListBounds) s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, bounds)
	if *s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec {
		sealed := s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec{}
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "SourceNodeIDExtensionIEIEValueProtocolIEContainerList"
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SourceNodeIDExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s13.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&codec))(s13.SourceNodeIDExtensionIEIEContainer(value), fresh, budget)
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, options aper.DecodeState) (s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eRABSecurityResultListIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSecurityResultListIEValue].
type ERABSecurityResultListIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s38.ERABSecurityResultListIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s38.ERABSecurityResultListIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEField(v *s38.ERABSecurityResultListIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s38.BridgeERABSecurityResultListIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s38.BridgeERABSecurityResultListIEFieldFieldReplay(v), *s38.BridgeERABSecurityResultListIEFieldFieldWithoutReplay(v))
}
func BridgeERABSecurityResultListIEValueCompareS1APProtocolIEField(v *s38.ERABSecurityResultListIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s38.BridgeERABSecurityResultListIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s38.BridgeERABSecurityResultListIEFieldFieldReplay(v), *s38.BridgeERABSecurityResultListIEFieldFieldWithoutReplay(v))
}

// securityResultExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SecurityResultExtIEsValue].
type SecurityResultExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SecurityResultExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SecurityResultExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// sensorMeasConfigNameItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SensorMeasConfigNameItemExtIEsValue].
type SensorMeasConfigNameItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SensorMeasConfigNameItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SensorMeasConfigNameItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionField(v *s13.SensorMeasConfigNameItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldReplay(v), *s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionField(v *s13.SensorMeasConfigNameItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldReplay(v), *s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldWithoutReplay(v))
}

// sensorMeasurementConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SensorMeasurementConfigurationExtIEsValue].
type SensorMeasurementConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.SensorMeasurementConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.SensorMeasurementConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s13.SensorMeasurementConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s13.SensorMeasurementConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// sensorNameConfigExtIEValueProtocolOpenValue is the concrete protocolOpenValue[SensorNameConfigExtIEValue].
type SensorNameConfigExtIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.SensorNameConfigExtIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.SensorNameConfigExtIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEField(v *s13.SensorNameConfigExtIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s07.BridgeSensorNameConfigExtIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s13.BridgeSensorNameConfigExtIEFieldFieldReplay(v), *s13.BridgeSensorNameConfigExtIEFieldFieldWithoutReplay(v))
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEField(v *s13.SensorNameConfigExtIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeSensorNameConfigExtIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s13.BridgeSensorNameConfigExtIEFieldFieldReplay(v), *s13.BridgeSensorNameConfigExtIEFieldFieldWithoutReplay(v))
}

// servedDCNsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ServedDCNsItemExtIEsValue].
type ServedDCNsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.ServedDCNsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.ServedDCNsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeServedDCNsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s13.ServedDCNsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeServedDCNsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeServedDCNsItemExtIEsExtFieldFieldReplay(v), *s13.BridgeServedDCNsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionField(v *s13.ServedDCNsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeServedDCNsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeServedDCNsItemExtIEsExtFieldFieldReplay(v), *s13.BridgeServedDCNsItemExtIEsExtFieldFieldWithoutReplay(v))
}

// servedGUMMEIsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ServedGUMMEIsItemExtIEsValue].
type ServedGUMMEIsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.ServedGUMMEIsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.ServedGUMMEIsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeServedGUMMEIsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s13.ServedGUMMEIsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeServedGUMMEIsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeServedGUMMEIsItemExtIEsExtFieldFieldReplay(v), *s13.BridgeServedGUMMEIsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionField(v *s13.ServedGUMMEIsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeServedGUMMEIsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeServedGUMMEIsItemExtIEsExtFieldFieldReplay(v), *s13.BridgeServedGUMMEIsItemExtIEsExtFieldFieldWithoutReplay(v))
}

// sourceNgRanNodeIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SourceNgRanNodeIDExtIEsValue].
type SourceNgRanNodeIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.SourceNgRanNodeIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.SourceNgRanNodeIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSourceNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionField(v *s13.SourceNgRanNodeIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeSourceNgRanNodeIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeSourceNgRanNodeIDExtIEsExtFieldFieldReplay(v), *s13.BridgeSourceNgRanNodeIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(v *s13.SourceNgRanNodeIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeSourceNgRanNodeIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeSourceNgRanNodeIDExtIEsExtFieldFieldReplay(v), *s13.BridgeSourceNgRanNodeIDExtIEsExtFieldFieldWithoutReplay(v))
}

// sourceeNBIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SourceeNBIDExtIEsValue].
type SourceeNBIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.SourceeNBIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.SourceeNBIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s13.SourceeNBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeSourceeNBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeSourceeNBIDExtIEsExtFieldFieldReplay(v), *s13.BridgeSourceeNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionField(v *s13.SourceeNBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeSourceeNBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeSourceeNBIDExtIEsExtFieldFieldReplay(v), *s13.BridgeSourceeNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldReplay(v), *s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionField(v *s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldReplay(v), *s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldWithoutReplay(v))
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

// SecurityResultAPERValue is the concrete APERValue[SecurityResult].
type SecurityResultAPERValue struct {
	context s00.BridgeCodecContext
	Value   s38.SecurityResult

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityResultAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityResultAPERValue) WithoutReplay() SecurityResultAPERValue {
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
	Value   SensorNameConfig

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

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSecurityResultExtIEsValueValidateS1APIEContainer(fields s13.SecurityResultExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSecurityResultExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSecurityResultExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSecurityResultExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APIEContainer(fields s13.SensorMeasConfigNameItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APIEContainer(fields s13.SensorMeasurementConfigurationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeServedDCNsItemExtIEsValueValidateS1APIEContainer(fields s13.ServedDCNsItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeServedDCNsItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeServedDCNsItemExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeServedDCNsItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeServedGUMMEIsItemExtIEsValueValidateS1APIEContainer(fields s13.ServedGUMMEIsItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeServedGUMMEIsItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeServedGUMMEIsItemExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeServedGUMMEIsItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSourceNgRanNodeIDExtIEsValueValidateS1APIEContainer(fields s13.SourceNgRanNodeIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeSourceNgRanNodeIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeSourceNgRanNodeIDExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeSourceNgRanNodeIDExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSourceeNBIDExtIEsValueValidateS1APIEContainer(fields s13.SourceeNBIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeSourceeNBIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeSourceeNBIDExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeSourceeNBIDExtIEsValueMethodRule(field.Value).Assignment
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

func BridgeERABSecurityResultListIEValueCaptureS1APERABIEContainerList(v *s38.ERABSecurityResultListIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSecurityResultListIEValueCompareS1APERABIEContainerList(v *s38.ERABSecurityResultListIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APERABIEContainerList(v *s13.SensorNameConfigExtIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APERABIEContainerList(v *s13.SensorNameConfigExtIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// sourceNodeIDExtensionIEIEValueProtocolOpenValue is the concrete protocolOpenValue[SourceNodeIDExtensionIEIEValue].
type SourceNodeIDExtensionIEIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.SourceNodeIDExtensionIEIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.SourceNodeIDExtensionIEIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APERABIEContainerList(v *s13.SourceNodeIDExtensionIEIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APERABIEContainerList(v *s13.SourceNodeIDExtensionIEIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEField(v *s13.SourceNodeIDExtensionIEIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s07.BridgeSourceNodeIDExtensionIEIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s13.BridgeSourceNodeIDExtensionIEIEFieldFieldReplay(v), *s13.BridgeSourceNodeIDExtensionIEIEFieldFieldWithoutReplay(v))
}
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEField(v *s13.SourceNodeIDExtensionIEIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeSourceNodeIDExtensionIEIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s13.BridgeSourceNodeIDExtensionIEIEFieldFieldReplay(v), *s13.BridgeSourceNodeIDExtensionIEIEFieldFieldWithoutReplay(v))
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
func BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEContainer(v *s38.ERABSecurityResultListIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSecurityResultListIEValueCompareS1APProtocolIEContainer(v *s38.ERABSecurityResultListIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainer(v *s13.SensorNameConfigExtIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainer(v *s13.SensorNameConfigExtIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEContainer(v *s13.SourceNodeIDExtensionIEIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainer(v *s13.SourceNodeIDExtensionIEIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

func BridgeERABSecurityResultListIEValueCaptureS1APProtocolErrorIEContainerList(v *s38.ERABSecurityResultListIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSecurityResultListIEValueCompareS1APProtocolErrorIEContainerList(v *s38.ERABSecurityResultListIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolErrorIEContainerList(v *s13.SensorNameConfigExtIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolErrorIEContainerList(v *s13.SensorNameConfigExtIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolErrorIEContainerList(v *s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(v *s13.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// ERABSecurityResultListIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABSecurityResultListIEValueProtocolIEContainerList].
type ERABSecurityResultListIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s38.ERABSecurityResultListIEValueProtocolIEContainerList, error)
	encode  func(s38.ERABSecurityResultListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s38.ERABSecurityResultListIEValueProtocolIEContainerList, aper.DecodeState) (s38.ERABSecurityResultListIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(s38.ERABSecurityResultListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) New(value s38.ERABSecurityResultListIEValueProtocolIEContainerList) (s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue {
			sealed := s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{Value: value}
			*s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldReplay(&sealed) = replay
			*s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) EncodeAPER(value s38.ERABSecurityResultListIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldContext(&value) == c.context && !fresh && (*s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s38.BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value s38.ERABSecurityResultListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) encodeChanged(value s38.ERABSecurityResultListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEContainerList(v *s38.ERABSecurityResultListIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSecurityResultListIEValueCompareS1APProtocolIEContainerList(v *s38.ERABSecurityResultListIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainerList(v *s13.SensorNameConfigExtIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainerList(v *s13.SensorNameConfigExtIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEContainerList(v *s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainerList(v *s13.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

func BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIESingleContainer(v *s13.SourceNodeIDExtensionIEIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIESingleContainer(v *s13.SourceNodeIDExtensionIEIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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
					s17.BridgeCaptureS1APDLCPSecurityInformation(v.rowDLCPSecurityInformation, s)
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
					s21.BridgeCaptureS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s08.BridgeCompareS1APUERadioCapability(v.rowUERadioCapability, s)
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
					s17.BridgeCompareS1APDLCPSecurityInformation(v.rowDLCPSecurityInformation, s)
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
					s21.BridgeCompareS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s08.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
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
func BridgeCaptureS1APERABSecurityResultList(v *s38.ERABSecurityResultList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABSecurityResultList(v *s38.ERABSecurityResultList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSecurityResultListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSensorMeasConfigNameItem(v *SensorMeasConfigNameItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APSensorNameConfig(&v.SensorNameConfig, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSensorMeasConfigNameItem(v *SensorMeasConfigNameItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APSensorNameConfig(&v.SensorNameConfig, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSensorMeasurementConfiguration(v *SensorMeasurementConfiguration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APSensorMeasConfig(&v.SensorMeasConfig, s)
	s.Bool(v.SensorMeasConfigNameList == nil)
	BridgeCompareS1APSensorMeasConfigNameList(&v.SensorMeasConfigNameList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSensorNameConfig(v *SensorNameConfig, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.SensorNameConfigChoiceUncompensatedBarometricConfig:
		{
			f := s.Begin()
			s.Bool(v.UncompensatedBarometricConfig == nil)
			if v.UncompensatedBarometricConfig != nil {
				s.Int(int64((*v.UncompensatedBarometricConfig)))
			}
			s.End(f, nil, false)
		}
	case s00.SensorNameConfigChoiceChoiceExtensions:
		{
			f := s.Begin()
			s.Bool(v.ChoiceExtensions == nil)
			if v.ChoiceExtensions != nil {
				BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSensorNameConfig(v *SensorNameConfig, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.SensorNameConfigChoiceUncompensatedBarometricConfig:
		{
			f := s.Begin()
			s.Bool(v.UncompensatedBarometricConfig == nil)
			if v.UncompensatedBarometricConfig != nil {
				s.Int(int64((*v.UncompensatedBarometricConfig)))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SensorNameConfigChoiceChoiceExtensions:
		{
			f := s.Begin()
			s.Bool(v.ChoiceExtensions == nil)
			if v.ChoiceExtensions != nil {
				BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
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
	s08.BridgeCompareS1APRelativeMMECapacity(&v.RelativeDCNCapacity, s)
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
	s08.BridgeCompareS1APServedPLMNs(&v.ServedPLMNs, s)
	s08.BridgeCompareS1APServedGroupIDs(&v.ServedGroupIDs, s)
	s08.BridgeCompareS1APServedMMECs(&v.ServedMMECs, s)
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
	s23.BridgeCaptureS1APGlobalRANNODEID(&v.GlobalRANNODEID, s)
	s21.BridgeCaptureS1APFiveGSTAI(&v.SelectedTAI, s)
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
	s23.BridgeCompareS1APGlobalRANNODEID(&v.GlobalRANNODEID, s)
	s21.BridgeCompareS1APFiveGSTAI(&v.SelectedTAI, s)
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
				s24.BridgeCaptureS1APSourceNodeIDExtension(v.SourceNodeIDExtension, s)
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
				s24.BridgeCompareS1APSourceNodeIDExtension(v.SourceNodeIDExtension, s)
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
			s36.BridgeCaptureS1APScheduledCommunicationTime(v.ScheduledCommunicationTime, s)
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
			s36.BridgeCompareS1APScheduledCommunicationTime(v.ScheduledCommunicationTime, s)
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
					s36.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(252):
			{
				f := s.Begin()
				s.Bool(v.rowUELevelQoSParameters == nil)
				if v.rowUELevelQoSParameters != nil {
					s21.BridgeCaptureS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s36.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(252):
			{
				f := s.Begin()
				s.Bool(v.rowUELevelQoSParameters == nil)
				if v.rowUELevelQoSParameters != nil {
					s21.BridgeCompareS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s08.BridgeCompareS1APUERadioCapability(v.rowUERadioCapability, s)
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
	IEExtensions        s13.ServedDCNsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	SensorNameConfig  SensorNameConfig                               `asn1:"tag:0,context,explicit"`
	IEExtensions      s13.SensorMeasConfigNameItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions                  s13.SensorMeasurementConfigurationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                                                 `asn1:"-" json:"-"`
	extCount                      int64                                                `asn1:"-" json:"-"`
	extPresent                    []bool                                               `asn1:"-" json:"-"`
	extData                       [][]byte                                             `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                                    `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding                               `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
}

// SensorNameConfig represents the ASN.1 CHOICE type SensorNameConfig.
type SensorNameConfig struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	received                      bool
	withoutReplay                 bool
	receivedAbsolute              bool
	receivedBytes                 aper.WireSpan
	receivedLocation              aper.Location
	Choice                        int
	perPadding                    aper.CompletePadding                                     `json:"-"`
	perOpenTypePadding            aper.CompletePadding                                     `json:"-"`
	UncompensatedBarometricConfig *int64                                                   `json:"UncompensatedBarometricConfig,omitempty"`
	ChoiceExtensions              *s13.SensorNameConfigExtIEValueProtocolIESingleContainer `json:"ChoiceExtensions,omitempty"`
}

// NewSensorNameConfigUncompensatedBarometricConfig creates a SensorNameConfig with the uncompensatedBarometricConfig alternative.
func BridgeNewSensorNameConfigUncompensatedBarometricConfigLegacy(v int64) SensorNameConfig {
	return SensorNameConfig{
		Choice:                        s00.SensorNameConfigChoiceUncompensatedBarometricConfig,
		UncompensatedBarometricConfig: &v,
	}
}

// NewSensorNameConfigChoiceExtensions creates a SensorNameConfig with the choice-Extensions alternative.
func BridgeNewSensorNameConfigChoiceExtensionsLegacy(v s13.SensorNameConfigExtIEValueProtocolIESingleContainer) SensorNameConfig {
	return SensorNameConfig{
		Choice:           s00.SensorNameConfigChoiceChoiceExtensions,
		ChoiceExtensions: &v,
	}
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
	SourceNodeIDExtension *s24.SourceNodeIDExtension `json:"SourceNodeIDExtension,omitempty"`
}

// NewSourceNodeIDSourceNgRanNodeID creates a SourceNodeID with the sourceNgRanNode-ID alternative.
func BridgeNewSourceNodeIDSourceNgRanNodeIDLegacy(v SourceNgRanNodeID) SourceNodeID {
	return SourceNodeID{
		Choice:            s00.SourceNodeIDChoiceSourceNgRanNodeID,
		SourceNgRanNodeID: &v,
	}
}

// NewSourceNodeIDSourceNodeIDExtension creates a SourceNodeID with the sourceNodeID-Extension alternative.
func BridgeNewSourceNodeIDSourceNodeIDExtensionLegacy(v s24.SourceNodeIDExtension) SourceNodeID {
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
	GlobalRANNODEID   s23.GlobalRANNODEID                     `asn1:"tag:0,context,explicit"`
	SelectedTAI       s21.FiveGSTAI                           `asn1:"tag:1,context,implicit"`
	IEExtensions      s13.SourceNgRanNodeIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions        s13.ServedGUMMEIsItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	ScheduledCommunicationTime     *s36.ScheduledCommunicationTime                              `asn1:"tag:2,context,implicit,optional" json:"ScheduledCommunicationTime,omitempty"`
	StationaryIndication           *int64                                                       `asn1:"tag:3,context,implicit,optional" json:"StationaryIndication,omitempty"`
	TrafficProfile                 *int64                                                       `asn1:"tag:4,context,implicit,optional" json:"TrafficProfile,omitempty"`
	BatteryIndication              *int64                                                       `asn1:"tag:5,context,implicit,optional" json:"BatteryIndication,omitempty"`
	IEExtensions                   s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer `asn1:"tag:6,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                                         `asn1:"-" json:"-"`
	extCount                       int64                                                        `asn1:"-" json:"-"`
	extPresent                     []bool                                                       `asn1:"-" json:"-"`
	extData                        [][]byte                                                     `asn1:"-" json:"-"`
	perPadding                     aper.FinalPadding                                            `asn1:"-" json:"-"`
	perExtPadding                  []aper.CompletePadding                                       `asn1:"-" json:"-"`
	extOrigin                      []aper.OpaqueOrigin
	extWire                        []aper.WireSpan
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.DCNID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding dCN-ID: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.RelativeDCNCapacity), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding relativeDCNCapacity: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeServedDCNsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ServedDCNsItem from APER format.
func (v *ServedDCNsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ServedDCNsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ServedDCNsItem{}
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
	val_dcnid, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "DCNID")
	}
	v.DCNID = s00.DCNID(val_dcnid)
	val_relativedcncapacity, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RelativeDCNCapacity")
	}
	v.RelativeDCNCapacity = s00.RelativeMMECapacity(val_relativedcncapacity)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.ServedDCNsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.ServedDCNsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERERABSecurityResultListListValue struct{ Value s38.ERABSecurityResultList }

// MarshalAPERERABSecurityResultListTo appends a ERABSecurityResultList list to bb.
func BridgeMarshalAPERERABSecurityResultListTo(list s38.ERABSecurityResultList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERERABSecurityResultListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s38.BridgeERABSecurityResultListIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
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
	if err := v.SensorNameConfig.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding sensorNameConfig: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SensorMeasConfigNameItem from APER format.
func (v *SensorMeasConfigNameItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *SensorMeasConfigNameItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorMeasConfigNameItem{}
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
	toleranceMark_sensornameconfig := bb.EnterComponent("SensorNameConfig")
	if err := v.SensorNameConfig.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SensorNameConfig")
	}
	bb.LeaveComponent(toleranceMark_sensornameconfig)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.SensorMeasConfigNameItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.SensorMeasConfigNameItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SensorMeasurementConfiguration from APER format.
func (v *SensorMeasurementConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *SensorMeasurementConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorMeasurementConfiguration{}
	var extAdditions aper.ExtensionAdditions
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
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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
		tmp_ieextensions := make(s13.SensorMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.SensorMeasurementConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SensorNameConfig to APER format.
func (v *SensorNameConfig) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SensorNameConfig) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("%s choice %d must be positive", "SensorNameConfig:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.SensorNameConfigChoiceUncompensatedBarometricConfig:
		if v.UncompensatedBarometricConfig == nil {
			return fmt.Errorf("choice alternative uncompensatedBarometricConfig is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.UncompensatedBarometricConfig), 1, true); err != nil {
			return fmt.Errorf("encoding uncompensatedBarometricConfig: %w", err)
		}
	case s00.SensorNameConfigChoiceChoiceExtensions:
		if v.ChoiceExtensions == nil {
			return fmt.Errorf("choice alternative choice-Extensions is nil")
		}
		if err := s13.BridgeSensorNameConfigExtIEFieldMethodMarshalAPERTo(v.ChoiceExtensions, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding choice-Extensions: %w", err)
		}
	default:
		return fmt.Errorf("unknown SensorNameConfig choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SensorNameConfig from APER format.
func (v *SensorNameConfig) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SensorNameConfig) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SensorNameConfig")
	}
	bb.EnterComponent("SensorNameConfig")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SensorNameConfig")
	}
	padding, err := aper.CaptureFinalBits(bb, "SensorNameConfig")
	if err != nil {
		return runtime.WrapDecodePath(err, "SensorNameConfig")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SensorNameConfig) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorNameConfig{}
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
	case s00.SensorNameConfigChoiceUncompensatedBarometricConfig:
		val_uncompensatedbarometricconfig, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UncompensatedBarometricConfig"})
		if err != nil {
			return runtime.WrapDecodePath(err, "UncompensatedBarometricConfig")
		}
		if err := aper.ChargeValue(bb, val_uncompensatedbarometricconfig); err != nil {
			return err
		}
		v.UncompensatedBarometricConfig = (*int64)(bb.OwnInt64(int64(val_uncompensatedbarometricconfig)))

	case s00.SensorNameConfigChoiceChoiceExtensions:
		toleranceMark_choiceextensions := bb.EnterComponent("ChoiceExtensions")
		var dec_choiceextensions s13.SensorNameConfigExtIEValueProtocolIESingleContainer
		if err := s13.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&dec_choiceextensions, bb); err != nil {
			return runtime.WrapDecodePath(err, "ChoiceExtensions")
		}
		if err := aper.ChargeValue(bb, dec_choiceextensions); err != nil {
			return err
		}
		v.ChoiceExtensions = &dec_choiceextensions
		bb.LeaveComponent(toleranceMark_choiceextensions)
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
		if err := s24.BridgeSourceNodeIDExtensionMethodMarshalAPERTo(v.SourceNodeIDExtension, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		var dec_sourcenodeidextension s24.SourceNodeIDExtension
		if err := s24.BridgeSourceNodeIDExtensionMethodUnmarshalAPERFrom(&dec_sourcenodeidextension, bb); err != nil {
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
	if err := s23.BridgeGlobalRANNODEIDMethodMarshalAPERTo(&v.GlobalRANNODEID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-RAN-NODE-ID: %w", err)
	}
	if err := s21.BridgeFiveGSTAIMethodMarshalAPERTo(&v.SelectedTAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding selected-TAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SourceNgRanNodeID from APER format.
func (v *SourceNgRanNodeID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *SourceNgRanNodeID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceNgRanNodeID{}
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
	toleranceMark_globalrannodeid := bb.EnterComponent("GlobalRANNODEID")
	if err := s23.BridgeGlobalRANNODEIDMethodUnmarshalAPERFrom(&v.GlobalRANNODEID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalRANNODEID")
	}
	bb.LeaveComponent(toleranceMark_globalrannodeid)
	toleranceMark_selectedtai := bb.EnterComponent("SelectedTAI")
	if err := s21.BridgeFiveGSTAIMethodUnmarshalAPERFrom(&v.SelectedTAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.SourceNgRanNodeIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.SourceNgRanNodeIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s13.BridgeServedGUMMEIsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ServedGUMMEIsItem from APER format.
func (v *ServedGUMMEIsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ServedGUMMEIsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ServedGUMMEIsItem{}
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
	toleranceMark_servedplmns := bb.EnterComponent("ServedPLMNs")
	v.ServedPLMNs = make(s00.ServedPLMNs, 0)
	_, errCollection_servedplmns := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_servedplmns, fragmentLength_servedplmns int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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
		tmp_ieextensions := make(s13.ServedGUMMEIsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.ServedGUMMEIsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		if err := s36.BridgeScheduledCommunicationTimeMethodMarshalAPERTo(v.ScheduledCommunicationTime, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SubscriptionBasedUEDifferentiationInfo from APER format.
func (v *SubscriptionBasedUEDifferentiationInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *SubscriptionBasedUEDifferentiationInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SubscriptionBasedUEDifferentiationInfo{}
	var extAdditions aper.ExtensionAdditions
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
		var dec_scheduledcommunicationtime s36.ScheduledCommunicationTime
		if err := s36.BridgeScheduledCommunicationTimeMethodUnmarshalAPERFrom(&dec_scheduledcommunicationtime, bb); err != nil {
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
		tmp_ieextensions := make(s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.SubscriptionBasedUEDifferentiationInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SensorMeasConfigNameItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SensorMeasConfigNameItem", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SensorMeasurementConfiguration", v.receivedLocation, v.perPadding)
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
func (v *SensorNameConfig) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SensorNameConfig", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SensorNameConfig", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SensorNameConfig) WithoutReplay() SensorNameConfig {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SensorNameConfig
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ServedDCNsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedDCNsItem", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedGUMMEIsItem", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SourceNgRanNodeID", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SourceNodeID", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SubscriptionBasedUEDifferentiationInfo", v.receivedLocation, v.perPadding)
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
func (v *SensorNameConfig) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SensorNameConfig")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SensorNameConfig) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SensorNameConfig")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSensorNameConfig(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SensorNameConfig")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SensorNameConfig")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SensorNameConfig) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SensorNameConfig")
}
func (v *SensorNameConfig) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SensorNameConfig")
}
func (v *SensorNameConfig) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSensorNameConfig(v, &s)
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
func (v *SensorNameConfig) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SensorNameConfig) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SensorNameConfig) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SensorNameConfig")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SensorNameConfig
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSensorNameConfig(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SensorNameConfig{}
		return report, aper.OperationError(err, "SensorNameConfig")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SensorNameConfig")
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

// NewSensorNameConfigUncompensatedBarometricConfig constructs a checked complete value.
func NewSensorNameConfigUncompensatedBarometricConfig(v int64, options ...aper.BuildOption) (SensorNameConfig, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigUncompensatedBarometricConfig")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigUncompensatedBarometricConfig")
	}
	value := BridgeNewSensorNameConfigUncompensatedBarometricConfigLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigUncompensatedBarometricConfig")
	}
	return value, aper.OperationError(nil, "SensorNameConfigUncompensatedBarometricConfig")
}

// NewSensorNameConfigChoiceExtensions constructs a checked complete value.
func NewSensorNameConfigChoiceExtensions(v s13.SensorNameConfigExtIEValueProtocolIESingleContainer, options ...aper.BuildOption) (SensorNameConfig, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigChoiceExtensions")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigChoiceExtensions")
	}
	value := BridgeNewSensorNameConfigChoiceExtensionsLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return SensorNameConfig{}, aper.OperationError(err, "SensorNameConfigChoiceExtensions")
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
func NewSourceNodeIDSourceNodeIDExtension(v s24.SourceNodeIDExtension, options ...aper.BuildOption) (SourceNodeID, error) {
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
	rowDLCPSecurityInformation                *s17.DLCPSecurityInformation
	rowCEModeBRestricted                      *s00.CEModeBRestricted
	rowEndIndication                          *s00.EndIndication
	rowSubscriptionBasedUEDifferentiationInfo *SubscriptionBasedUEDifferentiationInfo
	rowUELevelQoSParameters                   *s21.ERABLevelQoSParameters
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
func (v *ConnectionEstablishmentIndicationIEValue) AsDLCPSecurityInformation() (*s17.DLCPSecurityInformation, bool) {
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
func (v *ConnectionEstablishmentIndicationIEValue) AsUELevelQoSParameters() (*s21.ERABLevelQoSParameters, bool) {
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
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false)
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
		var value s17.DLCPSecurityInformation
		child := scope
		if err := s17.BridgeDLCPSecurityInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "DLCPSecurityInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DLCPSecurityInformation")
		if err != nil {
			return out, err
		}
		*s17.BridgeDLCPSecurityInformationFieldPerPadding(&value) = padding
		*s17.BridgeDLCPSecurityInformationFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeDLCPSecurityInformationFieldReceivedBytes(&value))
		*s17.BridgeDLCPSecurityInformationFieldReceivedLocation(&value) = raw.ContentLocation()
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
		var value s21.ERABLevelQoSParameters
		child := scope
		if err := s21.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UELevelQoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABLevelQoSParameters")
		if err != nil {
			return out, err
		}
		*s21.BridgeERABLevelQoSParametersFieldPerPadding(&value) = padding
		*s21.BridgeERABLevelQoSParametersFieldReceived(&value) = true
		raw.RetainContents(s21.BridgeERABLevelQoSParametersFieldReceivedBytes(&value))
		*s21.BridgeERABLevelQoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
		candidate, err := s17.BridgeDLCPSecurityInformationMethodMarshalAPERBudget(v.rowDLCPSecurityInformation, budget, fresh)
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
		candidate, err := s21.BridgeERABLevelQoSParametersMethodMarshalAPERBudget(v.rowUELevelQoSParameters, budget, fresh)
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
	rowSTMSI                                  *s36.STMSI
	rowUELevelQoSParameters                   *s21.ERABLevelQoSParameters
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
func (v *UEInformationTransferIEValue) AsSTMSI() (*s36.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}

// AsUELevelQoSParameters returns the selected UELevelQoSParameters value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsUELevelQoSParameters() (*s21.ERABLevelQoSParameters, bool) {
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
		var value s36.STMSI
		child := scope
		if err := s36.BridgeSTMSIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "STMSI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "STMSI")
		if err != nil {
			return out, err
		}
		*s36.BridgeSTMSIFieldPerPadding(&value) = padding
		*s36.BridgeSTMSIFieldReceived(&value) = true
		raw.RetainContents(s36.BridgeSTMSIFieldReceivedBytes(&value))
		*s36.BridgeSTMSIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSTMSI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(252):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s21.ERABLevelQoSParameters
		child := scope
		if err := s21.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UELevelQoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABLevelQoSParameters")
		if err != nil {
			return out, err
		}
		*s21.BridgeERABLevelQoSParametersFieldPerPadding(&value) = padding
		*s21.BridgeERABLevelQoSParametersFieldReceived(&value) = true
		raw.RetainContents(s21.BridgeERABLevelQoSParametersFieldReceivedBytes(&value))
		*s21.BridgeERABLevelQoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
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
		candidate, err := s36.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
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
		candidate, err := s21.BridgeERABLevelQoSParametersMethodMarshalAPERBudget(v.rowUELevelQoSParameters, budget, fresh)
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
			s08.BridgeCompareS1APUERadioCapability(&v, &s)
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
	return ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding{info: t.infoDLCPSecurityInformation(), codec: func() s17.DLCPSecurityInformationValueCodec {
		sealed := s17.DLCPSecurityInformationValueCodec{}
		*s17.BridgeDLCPSecurityInformationValueCodecFieldPath(&sealed) = "DLCPSecurityInformation"
		*s17.BridgeDLCPSecurityInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.DLCPSecurityInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.DLCPSecurityInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DLCPSecurityInformation")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(253), raw)
			if err != nil {
				var empty s17.DLCPSecurityInformation
				return empty, runtime.WrapDecodePath(err, "DLCPSecurityInformation")
			}
			value, ok := decoded.AsDLCPSecurityInformation()
			if !ok {
				var empty s17.DLCPSecurityInformation
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-DL-CP-SecurityInformation: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeDLCPSecurityInformationValueCodecFieldEncode(&sealed) = func(value s17.DLCPSecurityInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(253), rowDLCPSecurityInformation: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeDLCPSecurityInformationValueCodecFieldCapture(&sealed) = func(v s17.DLCPSecurityInformation, options aper.DecodeState) (s17.DLCPSecurityInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APDLCPSecurityInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s17.BridgeDLCPSecurityInformationValueCodecFieldCompare(&sealed) = func(v s17.DLCPSecurityInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APDLCPSecurityInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeDLCPSecurityInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLCPSecurityInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.DLCPSecurityInformation) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(253), rowDLCPSecurityInformation: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s17.DLCPSecurityInformation, bool) {
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
	return ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding{info: t.infoUELevelQoSParameters(), codec: func() s21.ERABLevelQoSParametersValueCodec {
		sealed := s21.ERABLevelQoSParametersValueCodec{}
		*s21.BridgeERABLevelQoSParametersValueCodecFieldPath(&sealed) = "ERABLevelQoSParameters"
		*s21.BridgeERABLevelQoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ERABLevelQoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s21.ERABLevelQoSParameters
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABLevelQoSParameters")
			var zero ConnectionEstablishmentIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(252), raw)
			if err != nil {
				var empty s21.ERABLevelQoSParameters
				return empty, runtime.WrapDecodePath(err, "ERABLevelQoSParameters")
			}
			value, ok := decoded.AsUELevelQoSParameters()
			if !ok {
				var empty s21.ERABLevelQoSParameters
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-UE-Level-QoS-Parameters: no selected value")
			}
			return *value, nil
		}
		*s21.BridgeERABLevelQoSParametersValueCodecFieldEncode(&sealed) = func(value s21.ERABLevelQoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(252), rowUELevelQoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s21.BridgeERABLevelQoSParametersValueCodecFieldCapture(&sealed) = func(v s21.ERABLevelQoSParameters, options aper.DecodeState) (s21.ERABLevelQoSParameters, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APERABLevelQoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeERABLevelQoSParametersValueCodecFieldCompare(&sealed) = func(v s21.ERABLevelQoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APERABLevelQoSParameters(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeERABLevelQoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABLevelQoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s21.ERABLevelQoSParameters) ConnectionEstablishmentIndicationIEValue {
			return ConnectionEstablishmentIndicationIEValue{id: s00.ProtocolIEID(252), rowUELevelQoSParameters: &value}
		}, get: func(value *ConnectionEstablishmentIndicationIEValue) (*s21.ERABLevelQoSParameters, bool) {
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
			s08.BridgeCompareS1APUERadioCapabilityID(&v, &s)
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

// CEModeBRestrictedCodec binds the complete APER value type.
func CEModeBRestrictedCodec() s00.CEModeBRestrictedValueCodec {
	return ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Codec()
}

// CoarseUELocationCodec binds the complete APER value type.
func CoarseUELocationCodec() s00.CoarseUELocationValueCodec {
	return ConnectionEstablishmentIndicationIEs().CoarseUELocation().Codec()
}

// DLCPSecurityInformationCodec binds the complete APER value type.
func DLCPSecurityInformationCodec() s17.DLCPSecurityInformationValueCodec {
	return ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Codec()
}

// ERABLevelQoSParametersCodec binds the complete APER value type.
func ERABLevelQoSParametersCodec() s21.ERABLevelQoSParametersValueCodec {
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

// SecurityResultCodec binds the complete source value type.
func SecurityResultCodec() SecurityResultValueCodec {
	return SecurityResultValueCodec{path: "SecurityResult", decode: func(data []byte, options aper.DecodeState) (s38.SecurityResult, error) {
		var value s38.SecurityResult
		if err := s38.BridgeSecurityResultMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s38.SecurityResult{}, err
		}
		*s38.BridgeSecurityResultFieldReceived(&value) = true
		*s38.BridgeSecurityResultFieldReceivedAbsolute(&value) = true
		*s38.BridgeSecurityResultFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s38.SecurityResult, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s38.BridgeSecurityResultMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s38.SecurityResult, options aper.DecodeState) (s38.SecurityResult, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s38.BridgeCaptureS1APSecurityResult(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s38.SecurityResult, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s38.BridgeCompareS1APSecurityResult(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityResult"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
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
	return SensorNameConfigValueCodec{path: "SensorNameConfig", decode: func(data []byte, options aper.DecodeState) (SensorNameConfig, error) {
		var value SensorNameConfig
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SensorNameConfig{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SensorNameConfig, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SensorNameConfig, options aper.DecodeState) (SensorNameConfig, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APSensorNameConfig(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SensorNameConfig, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSensorNameConfig(&v, &s)
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
func BridgeConnectionEstablishmentIndicationIEFieldFieldReplay(v *ConnectionEstablishmentIndicationIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeConnectionEstablishmentIndicationIEValueFieldId(v *ConnectionEstablishmentIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeConnectionEstablishmentIndicationIEValueFieldIsOpaque(v *ConnectionEstablishmentIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeConnectionEstablishmentIndicationIEValueFieldOpaque(v *ConnectionEstablishmentIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowCEModeBRestricted(v *ConnectionEstablishmentIndicationIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowCoarseUELocation(v *ConnectionEstablishmentIndicationIEValue) **s00.CoarseUELocation {
	return &v.rowCoarseUELocation
}
func BridgeConnectionEstablishmentIndicationIEValueFieldRowDLCPSecurityInformation(v *ConnectionEstablishmentIndicationIEValue) **s17.DLCPSecurityInformation {
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
func BridgeConnectionEstablishmentIndicationIEValueFieldRowUELevelQoSParameters(v *ConnectionEstablishmentIndicationIEValue) **s21.ERABLevelQoSParameters {
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
func BridgeConnectionEstablishmentIndicationIEValueMethodMatchesID(v ConnectionEstablishmentIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeConnectionEstablishmentIndicationIEValueMethodRule(v ConnectionEstablishmentIndicationIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeERABSecurityResultListValueCodecFieldCapture(v *ERABSecurityResultListValueCodec) *func(s38.ERABSecurityResultList, aper.DecodeState) (s38.ERABSecurityResultList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultListValueCodecFieldCompare(v *ERABSecurityResultListValueCodec) *func(s38.ERABSecurityResultList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultListValueCodecFieldContext(v *ERABSecurityResultListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListValueCodecFieldDecode(v *ERABSecurityResultListValueCodec) *func([]byte, aper.DecodeState) (s38.ERABSecurityResultList, error) {
	return &v.decode
}
func BridgeERABSecurityResultListValueCodecFieldEncode(v *ERABSecurityResultListValueCodec) *func(s38.ERABSecurityResultList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultListValueCodecFieldPath(v *ERABSecurityResultListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorMeasConfigNameItemMethodUnmarshalAPERFrom(v *SensorMeasConfigNameItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeSensorMeasurementConfigurationFieldPerPadding(v *SensorMeasurementConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSensorMeasurementConfigurationFieldReceived(v *SensorMeasurementConfiguration) *bool {
	return &v.received
}
func BridgeSensorMeasurementConfigurationFieldReceivedBytes(v *SensorMeasurementConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSensorMeasurementConfigurationFieldReceivedLocation(v *SensorMeasurementConfiguration) *aper.Location {
	return &v.receivedLocation
}
func BridgeSensorMeasurementConfigurationMethodMarshalAPERBudget(v *SensorMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSensorMeasurementConfigurationMethodUnmarshalAPERFrom(v *SensorMeasurementConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeServedDCNsItemMethodUnmarshalAPERFrom(v *ServedDCNsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeServedGUMMEIsItemMethodUnmarshalAPERFrom(v *ServedGUMMEIsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeSourceNodeIDFieldPerPadding(v *SourceNodeID) *aper.CompletePadding      { return &v.perPadding }
func BridgeSourceNodeIDFieldReceived(v *SourceNodeID) *bool                        { return &v.received }
func BridgeSourceNodeIDFieldReceivedBytes(v *SourceNodeID) *aper.WireSpan          { return &v.receivedBytes }
func BridgeSourceNodeIDFieldReceivedLocation(v *SourceNodeID) *aper.Location {
	return &v.receivedLocation
}
func BridgeSourceNodeIDMethodMarshalAPERBudget(v *SourceNodeID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSourceNodeIDMethodUnmarshalAPERFrom(v *SourceNodeID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeSubscriptionBasedUEDifferentiationInfoFieldPerPadding(v *SubscriptionBasedUEDifferentiationInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldReceived(v *SubscriptionBasedUEDifferentiationInfo) *bool {
	return &v.received
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedBytes(v *SubscriptionBasedUEDifferentiationInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedLocation(v *SubscriptionBasedUEDifferentiationInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudget(v *SubscriptionBasedUEDifferentiationInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERFrom(v *SubscriptionBasedUEDifferentiationInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldCodec(v *UEInformationTransferERABLevelQoSParametersIEBinding) *s21.ERABLevelQoSParametersValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldGet(v *UEInformationTransferERABLevelQoSParametersIEBinding) *func(*UEInformationTransferIEValue) (*s21.ERABLevelQoSParameters, bool) {
	return &v.get
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldInfo(v *UEInformationTransferERABLevelQoSParametersIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldInject(v *UEInformationTransferERABLevelQoSParametersIEBinding) *func(s21.ERABLevelQoSParameters) UEInformationTransferIEValue {
	return &v.inject
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
func BridgeUEInformationTransferIEFieldFieldReplay(v *UEInformationTransferIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeUEInformationTransferIEValueFieldId(v *UEInformationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEInformationTransferIEValueFieldIsOpaque(v *UEInformationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEInformationTransferIEValueFieldOpaque(v *UEInformationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEInformationTransferIEValueFieldRowMaskedIMEISV(v *UEInformationTransferIEValue) **s00.MaskedIMEISV {
	return &v.rowMaskedIMEISV
}
func BridgeUEInformationTransferIEValueFieldRowPendingDataIndication(v *UEInformationTransferIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgeUEInformationTransferIEValueFieldRowSTMSI(v *UEInformationTransferIEValue) **s36.STMSI {
	return &v.rowSTMSI
}
func BridgeUEInformationTransferIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *UEInformationTransferIEValue) **SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgeUEInformationTransferIEValueFieldRowUELevelQoSParameters(v *UEInformationTransferIEValue) **s21.ERABLevelQoSParameters {
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
func BridgeUEInformationTransferIEValueMethodEncodeFresh(v UEInformationTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEInformationTransferIEValueMethodMatchesID(v UEInformationTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEInformationTransferIEValueMethodRule(v UEInformationTransferIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeUEInformationTransferSTMSIIEBindingFieldCodec(v *UEInformationTransferSTMSIIEBinding) *s36.STMSIValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferSTMSIIEBindingFieldGet(v *UEInformationTransferSTMSIIEBinding) *func(*UEInformationTransferIEValue) (*s36.STMSI, bool) {
	return &v.get
}
func BridgeUEInformationTransferSTMSIIEBindingFieldInfo(v *UEInformationTransferSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferSTMSIIEBindingFieldInject(v *UEInformationTransferSTMSIIEBinding) *func(s36.STMSI) UEInformationTransferIEValue {
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
