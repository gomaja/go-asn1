// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s30 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s30

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	big "math/big"
)

// ConnectionEstablishmentIndicationIEContainer is the concrete ProtocolIEContainer[ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationIEContainer []ConnectionEstablishmentIndicationIEField

// ConnectionEstablishmentIndicationIEField is the concrete ProtocolIEField[ConnectionEstablishmentIndicationIEValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}
func BridgeERABSecurityResultListIEValueCaptureS1APProtocolIESingleContainer(v *ERABSecurityResultListIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSecurityResultListIEValueCompareS1APProtocolIESingleContainer(v *ERABSecurityResultListIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSecurityResultListIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIESingleContainer(v *s29.ERABToBeSetupItemHOReqIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIESingleContainer(v *s29.ERABToBeSetupItemHOReqIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s29.ERABToBeSwitchedDLItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s29.ERABToBeSwitchedDLItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIESingleContainer(v *ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIESingleContainer(v *ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIESingleContainer(v *s29.ERABToBeUpdatedItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIESingleContainer(v *s29.ERABToBeUpdatedItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecurityResultExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SecurityResultExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecurityResultExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecurityResultExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SecurityResultExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecurityResultExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SensorMeasConfigNameItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SensorMeasConfigNameItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SensorMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SensorMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIESingleContainer(v *s11.SensorNameConfigExtIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(v *s11.SensorNameConfigExtIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEField(v, s)
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

// ERABSecurityResultListIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABSecurityResultListIEValue].
type ERABSecurityResultListIEValueProtocolIESingleContainer = ERABSecurityResultListIEField

// ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABToBeSwitchedDLItemIEValue].
type ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer = ERABToBeSwitchedDLItemIEField

// ERABSecurityResultListERABSecurityResultItemIEBinding is the concrete IEBinding[ERABSecurityResultItem, ERABSecurityResultListIEValue].
type ERABSecurityResultListERABSecurityResultItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABSecurityResultItemValueCodec
	inject func(ERABSecurityResultItem,

	) ERABSecurityResultListIEValue

	get func(*ERABSecurityResultListIEValue,

	) (*ERABSecurityResultItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSecurityResultListERABSecurityResultItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSecurityResultListERABSecurityResultItemIEBinding) Codec() ERABSecurityResultItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSecurityResultListERABSecurityResultItemIEBinding) New(value ERABSecurityResultItem,

) (ERABSecurityResultListIEField, error) {
	if b.inject == nil {
		return ERABSecurityResultListIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultListIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABSecurityResultListIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSecurityResultListIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSecurityResultListIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSecurityResultListERABSecurityResultItemIEBinding) Get(field *ERABSecurityResultListIEField) (*ERABSecurityResultItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSecurityResultItemValueCodec is the concrete ValueCodec[ERABSecurityResultItem].
type ERABSecurityResultItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultItem,

		error)
	encode func(ERABSecurityResultItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultItem, aper.DecodeState,

	) (ERABSecurityResultItem, aper.Snapshot,

	)
	compare func(ERABSecurityResultItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultItemValueCodec) New(value ERABSecurityResultItem,

) (ERABSecurityResultItemAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultItemValueCodec) EncodeAPER(value ERABSecurityResultItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultItemValueCodec) encodeBudgetValue(value ERABSecurityResultItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultItemValueCodec) encodeChanged(value ERABSecurityResultItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSecurityResultListIEField is the concrete ProtocolIEField[ERABSecurityResultListIEValue].
type ERABSecurityResultListIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABSecurityResultListIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultListIEField) WithoutReplay() ERABSecurityResultListIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSecurityResultListIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSecurityResultListIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABSecurityResultListIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSecurityResultListIEField{}
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
	var zero ERABSecurityResultListIEValue

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
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultList,

		error)
	encode func(ERABSecurityResultList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultList, aper.DecodeState,

	) (ERABSecurityResultList, aper.Snapshot,

	)
	compare func(ERABSecurityResultList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultListValueCodec) New(value ERABSecurityResultList,

) (ERABSecurityResultListAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultListValueCodec) EncodeAPER(value ERABSecurityResultListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultListValueCodec) encodeBudgetValue(value ERABSecurityResultList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultListValueCodec) encodeChanged(value ERABSecurityResultList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, ConnectionEstablishmentIndicationIEValue].
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

// ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding is the concrete IEBinding[EnhancedCoverageRestricted, ConnectionEstablishmentIndicationIEValue].
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

// ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding is the concrete IEBinding[DLCPSecurityInformation, ConnectionEstablishmentIndicationIEValue].
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

// ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding is the concrete IEBinding[CEModeBRestricted, ConnectionEstablishmentIndicationIEValue].
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

// ConnectionEstablishmentIndicationEndIndicationIEBinding is the concrete IEBinding[EndIndication, ConnectionEstablishmentIndicationIEValue].
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

// ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding is the concrete IEBinding[ERABLevelQoSParameters, ConnectionEstablishmentIndicationIEValue].
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

// ConnectionEstablishmentIndicationCoarseUELocationIEBinding is the concrete IEBinding[CoarseUELocation, ConnectionEstablishmentIndicationIEValue].
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

// ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding is the concrete IEBinding[ERABToBeSwitchedDLItem, ERABToBeSwitchedDLItemIEValue].
type ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABToBeSwitchedDLItemValueCodec
	inject func(ERABToBeSwitchedDLItem,

	) ERABToBeSwitchedDLItemIEValue

	get func(*ERABToBeSwitchedDLItemIEValue,

	) (*ERABToBeSwitchedDLItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding) Codec() ERABToBeSwitchedDLItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding) New(value ERABToBeSwitchedDLItem,

) (ERABToBeSwitchedDLItemIEField, error) {
	if b.inject == nil {
		return ERABToBeSwitchedDLItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSwitchedDLItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSwitchedDLItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding) Get(field *ERABToBeSwitchedDLItemIEField) (*ERABToBeSwitchedDLItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABToBeSwitchedDLItemValueCodec is the concrete ValueCodec[ERABToBeSwitchedDLItem].
type ERABToBeSwitchedDLItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItem,

		error)
	encode func(ERABToBeSwitchedDLItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLItem, aper.DecodeState,

	) (ERABToBeSwitchedDLItem, aper.Snapshot,

	)
	compare func(ERABToBeSwitchedDLItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLItemValueCodec) New(value ERABToBeSwitchedDLItem,

) (ERABToBeSwitchedDLItemAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLItemValueCodec) EncodeAPER(value ERABToBeSwitchedDLItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLItemValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLItemValueCodec) encodeChanged(value ERABToBeSwitchedDLItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedDLItemIEField is the concrete ProtocolIEField[ERABToBeSwitchedDLItemIEValue].
type ERABToBeSwitchedDLItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSwitchedDLItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemIEField) WithoutReplay() ERABToBeSwitchedDLItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSwitchedDLItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSwitchedDLItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSwitchedDLItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSwitchedDLItemIEField{}
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
	var zero ERABToBeSwitchedDLItemIEValue

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

// ERABToBeSetupListHOReqValueCodec is the concrete ValueCodec[ERABToBeSetupListHOReq].
type ERABToBeSetupListHOReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s29.ERABToBeSetupListHOReq,

		error)
	encode func(s29.ERABToBeSetupListHOReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s29.ERABToBeSetupListHOReq, aper.DecodeState,

	) (s29.ERABToBeSetupListHOReq, aper.Snapshot,

	)
	compare func(s29.ERABToBeSetupListHOReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupListHOReqValueCodec) New(value s29.ERABToBeSetupListHOReq,

) (s29.ERABToBeSetupListHOReqAPERValue, error) {
	if c.encode == nil {
		return s29.ERABToBeSetupListHOReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s29.ERABToBeSetupListHOReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s29.ERABToBeSetupListHOReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s29.ERABToBeSetupListHOReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupListHOReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s29.ERABToBeSetupListHOReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s29.ERABToBeSetupListHOReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s29.ERABToBeSetupListHOReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s29.ERABToBeSetupListHOReqAPERValue {
			sealed := s29.ERABToBeSetupListHOReqAPERValue{Value: value}
			*s29.BridgeERABToBeSetupListHOReqAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s29.BridgeERABToBeSetupListHOReqAPERValueFieldReplay(&sealed) = replay
			*s29.BridgeERABToBeSetupListHOReqAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s29.ERABToBeSetupListHOReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupListHOReqValueCodec) EncodeAPER(value s29.ERABToBeSetupListHOReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s29.BridgeERABToBeSetupListHOReqAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s29.BridgeERABToBeSetupListHOReqAPERValueFieldContext(&value) == c.context && !fresh && (*s29.BridgeERABToBeSetupListHOReqAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s29.BridgeERABToBeSetupListHOReqAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s29.BridgeERABToBeSetupListHOReqAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s29.BridgeERABToBeSetupListHOReqAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABToBeSetupListHOReqValueCodec) encodeBudgetValue(value s29.ERABToBeSetupListHOReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupListHOReqValueCodec) encodeChanged(value s29.ERABToBeSetupListHOReq,

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

// ERABToBeSwitchedDLListValueCodec is the concrete ValueCodec[ERABToBeSwitchedDLList].
type ERABToBeSwitchedDLListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLList,

		error)
	encode func(ERABToBeSwitchedDLList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLList, aper.DecodeState,

	) (ERABToBeSwitchedDLList, aper.Snapshot,

	)
	compare func(ERABToBeSwitchedDLList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLListValueCodec) New(value ERABToBeSwitchedDLList,

) (ERABToBeSwitchedDLListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLListValueCodec) EncodeAPER(value ERABToBeSwitchedDLListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLListValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLListValueCodec) encodeChanged(value ERABToBeSwitchedDLList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecurityResultValueCodec is the concrete ValueCodec[SecurityResult].
type SecurityResultValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecurityResult,

		error)
	encode func(SecurityResult,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityResult, aper.DecodeState,

	) (SecurityResult, aper.Snapshot,

	)
	compare func(SecurityResult, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityResultValueCodec) New(value SecurityResult,

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
func (c SecurityResultValueCodec) encodeBudgetValue(value SecurityResult,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityResultValueCodec) encodeChanged(value SecurityResult,

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
func BridgeERABSecurityResultListIEValueValidateS1APIEContainer(fields ERABSecurityResultListIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// ERABSecurityResultListIEContainer is the concrete ProtocolIEContainer[ERABSecurityResultListIEValue].
type ERABSecurityResultListIEContainer []ERABSecurityResultListIEField

func BridgeERABToBeSetupItemHOReqExtIEsValueValidateS1APExtensionContainer(fields s29.ERABToBeSetupItemHOReqExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s29.ERABToBeSetupItemHOReqExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s29.ERABToBeSetupItemHOReqExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeERABToBeSetupItemHOReqExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABToBeSetupItemHOReqIEValueValidateS1APIEContainer(fields s29.ERABToBeSetupItemHOReqIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s29.BridgeERABToBeSetupItemHOReqIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s29.BridgeERABToBeSetupItemHOReqIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s29.BridgeERABToBeSetupItemHOReqIEValueMethodRule(field.Value).Assignment
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
func BridgeERABToBeSwitchedDLItemExtIEsValueValidateS1APExtensionContainer(fields s29.ERABToBeSwitchedDLItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s29.ERABToBeSwitchedDLItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s29.ERABToBeSwitchedDLItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeERABToBeSwitchedDLItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABToBeSwitchedDLItemIEValueValidateS1APIEContainer(fields ERABToBeSwitchedDLItemIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// ERABToBeSwitchedDLItemIEContainer is the concrete ProtocolIEContainer[ERABToBeSwitchedDLItemIEValue].
type ERABToBeSwitchedDLItemIEContainer []ERABToBeSwitchedDLItemIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABToBeUpdatedItemIEValueValidateS1APIEContainer(fields s29.ERABToBeUpdatedItemIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s29.BridgeERABToBeUpdatedItemIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s29.BridgeERABToBeUpdatedItemIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s29.BridgeERABToBeUpdatedItemIEValueMethodRule(field.Value).Assignment
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
func BridgeSecurityIndicationExtIEsValueValidateS1APExtensionContainer(fields s11.SecurityIndicationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SecurityIndicationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SecurityIndicationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSecurityIndicationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSecurityResultExtIEsValueValidateS1APExtensionContainer(fields s11.SecurityResultExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SecurityResultExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SecurityResultExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSecurityResultExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APExtensionContainer(fields s11.SensorMeasConfigNameItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SensorMeasConfigNameItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SensorMeasConfigNameItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields s11.SensorMeasurementConfigurationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SensorMeasurementConfigurationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SensorMeasurementConfigurationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
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
func ERABSecurityResultListIEValueERABIEContainerListCodec(table s00.ERABSecurityResultListIEValueIETable) ERABSecurityResultListIEValueERABIEContainerListValueCodec {
	codec := ERABSecurityResultListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABSecurityResultListIEValueERABIEContainerListValueCodec{}
	}
	return ERABSecurityResultListIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSecurityResultListIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABSecurityResultListIEValueERABIEContainerList(value), err
	}, encode: func(value ERABSecurityResultListIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABSecurityResultListIEContainer(value), fresh, budget)
	}, capture: func(v ERABSecurityResultListIEValueERABIEContainerList, options aper.DecodeState) (ERABSecurityResultListIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSecurityResultListIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABSecurityResultListIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABSecurityResultListIEValueCompareS1APERABIEContainerList(&v, &s)
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
func ERABToBeSetupItemHOReqIEValueERABIEContainerListCodec(table s00.ERABToBeSetupItemHOReqIEValueIETable) s29.ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec {
	codec := ERABToBeSetupItemHOReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec{}
	}
	return func() s29.ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec {
		sealed := s29.ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec{}
		*s29.BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEValueERABIEContainerList, error) {
			value, err := (*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s29.ERABToBeSetupItemHOReqIEValueERABIEContainerList(value), err
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeSetupItemHOReqIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldEncode(&codec))(s29.ERABToBeSetupItemHOReqIEContainer(value), fresh, budget)
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEValueERABIEContainerList, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSwitchedDLItemIEValueERABIEContainerListCodec(table s00.ERABToBeSwitchedDLItemIEValueIETable) ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec {
	codec := ERABToBeSwitchedDLItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec{}
	}
	return ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSwitchedDLItemIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSwitchedDLItemIEValueERABIEContainerList(value), err
	}, encode: func(value ERABToBeSwitchedDLItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSwitchedDLItemIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSwitchedDLItemIEValueERABIEContainerList, options aper.DecodeState) (ERABToBeSwitchedDLItemIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSwitchedDLItemIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeSwitchedDLItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSwitchedDLItemIEValueCompareS1APERABIEContainerList(&v, &s)
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
func ERABToBeUpdatedItemIEValueERABIEContainerListCodec(table s00.ERABToBeUpdatedItemIEValueIETable) s29.ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec {
	codec := ERABToBeUpdatedItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s29.ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec {
		sealed := s29.ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec{}
		*s29.BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEValueERABIEContainerList, error) {
			value, err := (*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s29.ERABToBeUpdatedItemIEValueERABIEContainerList(value), err
		}
		*s29.BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeUpdatedItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldEncode(&codec))(s29.ERABToBeUpdatedItemIEContainer(value), fresh, budget)
		}
		*s29.BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeUpdatedItemIEValueERABIEContainerList, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeUpdatedItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SensorNameConfigExtIEValueERABIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable) s11.SensorNameConfigExtIEValueERABIEContainerListValueCodec {
	codec := SensorNameConfigExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SensorNameConfigExtIEValueERABIEContainerListValueCodec{}
	}
	return func() s11.SensorNameConfigExtIEValueERABIEContainerListValueCodec {
		sealed := s11.SensorNameConfigExtIEValueERABIEContainerListValueCodec{}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorNameConfigExtIEValueERABIEContainerList, error) {
			value, err := (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s11.SensorNameConfigExtIEValueERABIEContainerList(value), err
		}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SensorNameConfigExtIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s11.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SensorNameConfigExtIEValueERABIEContainerList, options aper.DecodeState) (s11.SensorNameConfigExtIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SensorNameConfigExtIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
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
func SourceNodeIDExtensionIEIEValueERABIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable) s11.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec{}
	}
	return func() s11.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec {
		sealed := s11.SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec{}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, error) {
			value, err := (*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s11.SourceNodeIDExtensionIEIEValueERABIEContainerList(value), err
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(&codec))(s11.SourceNodeIDExtensionIEIEContainer(value), fresh, budget)
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
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
func ERABToBeSwitchedDLItemExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeSwitchedDLItemExtIEsValueExtensionTable) s29.ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeSwitchedDLItemExtIEsValueExtensionTableFieldBound(&table) {
		return s29.ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec{}
	}
	return func() s29.ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec {
		sealed := s29.ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec{}
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeSwitchedDLItemExtIEsExtField, error) {
			var field s29.ERABToBeSwitchedDLItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s29.ERABToBeSwitchedDLItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeSwitchedDLItemExtIEsExtField, options aper.DecodeState) (s29.ERABToBeSwitchedDLItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedDLItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeSwitchedDLItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedDLItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SecurityResultExtIEsValueExtensionFieldTableCodec(table s00.SecurityResultExtIEsValueExtensionTable) s11.SecurityResultExtIEsExtFieldValueCodec {
	if !*s00.BridgeSecurityResultExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SecurityResultExtIEsExtFieldValueCodec{}
	}
	return func() s11.SecurityResultExtIEsExtFieldValueCodec {
		sealed := s11.SecurityResultExtIEsExtFieldValueCodec{}
		*s11.BridgeSecurityResultExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SecurityResultExtIEsExtField, error) {
			var field s11.SecurityResultExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSecurityResultExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSecurityResultExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SecurityResultExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSecurityResultExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSecurityResultExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SecurityResultExtIEsExtField, options aper.DecodeState) (s11.SecurityResultExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecurityResultExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSecurityResultExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SecurityResultExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecurityResultExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSecurityResultExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SensorMeasConfigNameItemExtIEsValueExtensionFieldTableCodec(table s00.SensorMeasConfigNameItemExtIEsValueExtensionTable) s11.SensorMeasConfigNameItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeSensorMeasConfigNameItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SensorMeasConfigNameItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.SensorMeasConfigNameItemExtIEsExtFieldValueCodec {
		sealed := s11.SensorMeasConfigNameItemExtIEsExtFieldValueCodec{}
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorMeasConfigNameItemExtIEsExtField, error) {
			var field s11.SensorMeasConfigNameItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SensorMeasConfigNameItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SensorMeasConfigNameItemExtIEsExtField, options aper.DecodeState) (s11.SensorMeasConfigNameItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SensorMeasConfigNameItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SensorMeasurementConfigurationExtIEsValueExtensionFieldTableCodec(table s00.SensorMeasurementConfigurationExtIEsValueExtensionTable) s11.SensorMeasurementConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeSensorMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SensorMeasurementConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s11.SensorMeasurementConfigurationExtIEsExtFieldValueCodec {
		sealed := s11.SensorMeasurementConfigurationExtIEsExtFieldValueCodec{}
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorMeasurementConfigurationExtIEsExtField, error) {
			var field s11.SensorMeasurementConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SensorMeasurementConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SensorMeasurementConfigurationExtIEsExtField, options aper.DecodeState) (s11.SensorMeasurementConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SensorMeasurementConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.ServedDCNsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeServedDCNsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.ServedGUMMEIsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeServedGUMMEIsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SourceNgRanNodeIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SourceeNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
func ERABToBeSwitchedDLItemExtIEsValueExtensionTableCodec(table s00.ERABToBeSwitchedDLItemExtIEsValueExtensionTable, bounds aper.ListBounds) s29.ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeSwitchedDLItemExtIEsValueExtensionTableFieldBound(&table) {
		return s29.ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s29.ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec {
		sealed := s29.ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec{}
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeSwitchedDLItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s29.ERABToBeSwitchedDLItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s29.ERABToBeSwitchedDLItemExtIEsExtField
					if err := s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s29.ERABToBeSwitchedDLItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeSwitchedDLItemExtIEsExtContainer, options aper.DecodeState) (s29.ERABToBeSwitchedDLItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedDLItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeSwitchedDLItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABToBeSwitchedDLItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SecurityResultExtIEsValueExtensionTableCodec(table s00.SecurityResultExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SecurityResultExtIEsExtContainerValueCodec {
	if !*s00.BridgeSecurityResultExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SecurityResultExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SecurityResultExtIEsExtContainerValueCodec {
		sealed := s11.SecurityResultExtIEsExtContainerValueCodec{}
		*s11.BridgeSecurityResultExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SecurityResultExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SecurityResultExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SecurityResultExtIEsExtField
					if err := s11.BridgeSecurityResultExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSecurityResultExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SecurityResultExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSecurityResultExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSecurityResultExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SecurityResultExtIEsExtContainer, options aper.DecodeState) (s11.SecurityResultExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecurityResultExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSecurityResultExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SecurityResultExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSecurityResultExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSecurityResultExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SensorMeasConfigNameItemExtIEsValueExtensionTableCodec(table s00.SensorMeasConfigNameItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SensorMeasConfigNameItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeSensorMeasConfigNameItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SensorMeasConfigNameItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SensorMeasConfigNameItemExtIEsExtContainerValueCodec {
		sealed := s11.SensorMeasConfigNameItemExtIEsExtContainerValueCodec{}
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorMeasConfigNameItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SensorMeasConfigNameItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SensorMeasConfigNameItemExtIEsExtField
					if err := s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SensorMeasConfigNameItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SensorMeasConfigNameItemExtIEsExtContainer, options aper.DecodeState) (s11.SensorMeasConfigNameItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SensorMeasConfigNameItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SensorMeasurementConfigurationExtIEsValueExtensionTableCodec(table s00.SensorMeasurementConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SensorMeasurementConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeSensorMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SensorMeasurementConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SensorMeasurementConfigurationExtIEsExtContainerValueCodec {
		sealed := s11.SensorMeasurementConfigurationExtIEsExtContainerValueCodec{}
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorMeasurementConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SensorMeasurementConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SensorMeasurementConfigurationExtIEsExtField
					if err := s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SensorMeasurementConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SensorMeasurementConfigurationExtIEsExtContainer, options aper.DecodeState) (s11.SensorMeasurementConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SensorMeasurementConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
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
					if err := s11.BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			f := s.
				Begin()
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
					if err := s11.BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			f := s.
				Begin()
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
					if err := s11.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			f := s.
				Begin()
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
					if err := s11.BridgeSourceeNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			f := s.
				Begin()
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
func ERABSecurityResultListIEValueIEFieldTableCodec(table s00.ERABSecurityResultListIEValueIETable) ERABSecurityResultListIEFieldValueCodec {
	if !*s00.BridgeERABSecurityResultListIEValueIETableFieldBound(&table) {
		return ERABSecurityResultListIEFieldValueCodec{}
	}
	return ERABSecurityResultListIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSecurityResultListIEField, error) {
		var field ERABSecurityResultListIEField
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
	}, encode: func(field ERABSecurityResultListIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABSecurityResultListIEField, options aper.DecodeState) (ERABSecurityResultListIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABSecurityResultListIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABSecurityResultListIEValueCompareS1APProtocolIEField(&v, &s)
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
func ERABToBeSetupItemHOReqIEValueIEFieldTableCodec(table s00.ERABToBeSetupItemHOReqIEValueIETable) s29.ERABToBeSetupItemHOReqIEFieldValueCodec {
	if !*s00.BridgeERABToBeSetupItemHOReqIEValueIETableFieldBound(&table) {
		return s29.ERABToBeSetupItemHOReqIEFieldValueCodec{}
	}
	return func() s29.ERABToBeSetupItemHOReqIEFieldValueCodec {
		sealed := s29.ERABToBeSetupItemHOReqIEFieldValueCodec{}
		*s29.BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEField, error) {
			var field s29.ERABToBeSetupItemHOReqIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s29.BridgeERABToBeSetupItemHOReqIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s29.BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldEncode(&sealed) = func(field s29.ERABToBeSetupItemHOReqIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s29.BridgeERABToBeSetupItemHOReqIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s29.BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEField, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s29.BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSwitchedDLItemIEValueIEFieldTableCodec(table s00.ERABToBeSwitchedDLItemIEValueIETable) ERABToBeSwitchedDLItemIEFieldValueCodec {
	if !*s00.BridgeERABToBeSwitchedDLItemIEValueIETableFieldBound(&table) {
		return ERABToBeSwitchedDLItemIEFieldValueCodec{}
	}
	return ERABToBeSwitchedDLItemIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSwitchedDLItemIEField, error) {
		var field ERABToBeSwitchedDLItemIEField
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
	}, encode: func(field ERABToBeSwitchedDLItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABToBeSwitchedDLItemIEField, options aper.DecodeState) (ERABToBeSwitchedDLItemIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABToBeSwitchedDLItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIEField(&v, &s)
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
func ERABToBeUpdatedItemIEValueIEFieldTableCodec(table s00.ERABToBeUpdatedItemIEValueIETable) s29.ERABToBeUpdatedItemIEFieldValueCodec {
	if !*s00.BridgeERABToBeUpdatedItemIEValueIETableFieldBound(&table) {
		return s29.ERABToBeUpdatedItemIEFieldValueCodec{}
	}
	return func() s29.ERABToBeUpdatedItemIEFieldValueCodec {
		sealed := s29.ERABToBeUpdatedItemIEFieldValueCodec{}
		*s29.BridgeERABToBeUpdatedItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEField, error) {
			var field s29.ERABToBeUpdatedItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s29.BridgeERABToBeUpdatedItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s29.BridgeERABToBeUpdatedItemIEFieldValueCodecFieldEncode(&sealed) = func(field s29.ERABToBeUpdatedItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s29.BridgeERABToBeUpdatedItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s29.BridgeERABToBeUpdatedItemIEFieldValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeUpdatedItemIEField, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s29.BridgeERABToBeUpdatedItemIEFieldValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeUpdatedItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeUpdatedItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SensorNameConfigExtIEValueIEFieldTableCodec(table s00.SensorNameConfigExtIEValueIETable) s11.SensorNameConfigExtIEFieldValueCodec {
	if !*s00.BridgeSensorNameConfigExtIEValueIETableFieldBound(&table) {
		return s11.SensorNameConfigExtIEFieldValueCodec{}
	}
	return func() s11.SensorNameConfigExtIEFieldValueCodec {
		sealed := s11.SensorNameConfigExtIEFieldValueCodec{}
		*s11.BridgeSensorNameConfigExtIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorNameConfigExtIEField, error) {
			var field s11.SensorNameConfigExtIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSensorNameConfigExtIEFieldValueCodecFieldEncode(&sealed) = func(field s11.SensorNameConfigExtIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSensorNameConfigExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSensorNameConfigExtIEFieldValueCodecFieldCapture(&sealed) = func(v s11.SensorNameConfigExtIEField, options aper.DecodeState) (s11.SensorNameConfigExtIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s11.BridgeSensorNameConfigExtIEFieldValueCodecFieldCompare(&sealed) = func(v s11.SensorNameConfigExtIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorNameConfigExtIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
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
			BridgeSourceNodeIDExtensionIEIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
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
func ERABSecurityResultListIEValueIETableCodec(table s00.ERABSecurityResultListIEValueIETable, bounds aper.ListBounds) ERABSecurityResultListIEContainerValueCodec {
	if !*s00.BridgeERABSecurityResultListIEValueIETableFieldBound(&table) {
		return ERABSecurityResultListIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABSecurityResultListIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSecurityResultListIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABSecurityResultListIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABSecurityResultListIEField
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
		encode: func(fields ERABSecurityResultListIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABSecurityResultListIEContainer, options aper.DecodeState) (ERABSecurityResultListIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABSecurityResultListIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSecurityResultListIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func ERABToBeSetupItemHOReqIEValueIETableCodec(table s00.ERABToBeSetupItemHOReqIEValueIETable, bounds aper.ListBounds) s29.ERABToBeSetupItemHOReqIEContainerValueCodec {
	if !*s00.BridgeERABToBeSetupItemHOReqIEValueIETableFieldBound(&table) {
		return s29.ERABToBeSetupItemHOReqIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s29.ERABToBeSetupItemHOReqIEContainerValueCodec {
		sealed := s29.ERABToBeSetupItemHOReqIEContainerValueCodec{}
		*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s29.ERABToBeSetupItemHOReqIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s29.ERABToBeSetupItemHOReqIEField
					if err := s29.BridgeERABToBeSetupItemHOReqIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldEncode(&sealed) = func(fields s29.ERABToBeSetupItemHOReqIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s29.BridgeERABToBeSetupItemHOReqIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEContainer, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSwitchedDLItemIEValueIETableCodec(table s00.ERABToBeSwitchedDLItemIEValueIETable, bounds aper.ListBounds) ERABToBeSwitchedDLItemIEContainerValueCodec {
	if !*s00.BridgeERABToBeSwitchedDLItemIEValueIETableFieldBound(&table) {
		return ERABToBeSwitchedDLItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABToBeSwitchedDLItemIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSwitchedDLItemIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeSwitchedDLItemIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeSwitchedDLItemIEField
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
		encode: func(fields ERABToBeSwitchedDLItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABToBeSwitchedDLItemIEContainer, options aper.DecodeState) (ERABToBeSwitchedDLItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSwitchedDLItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func ERABToBeUpdatedItemIEValueIETableCodec(table s00.ERABToBeUpdatedItemIEValueIETable, bounds aper.ListBounds) s29.ERABToBeUpdatedItemIEContainerValueCodec {
	if !*s00.BridgeERABToBeUpdatedItemIEValueIETableFieldBound(&table) {
		return s29.ERABToBeUpdatedItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s29.ERABToBeUpdatedItemIEContainerValueCodec {
		sealed := s29.ERABToBeUpdatedItemIEContainerValueCodec{}
		*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s29.ERABToBeUpdatedItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s29.ERABToBeUpdatedItemIEField
					if err := s29.BridgeERABToBeUpdatedItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s29.ERABToBeUpdatedItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s29.BridgeERABToBeUpdatedItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeUpdatedItemIEContainer, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeUpdatedItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SensorNameConfigExtIEValueIETableCodec(table s00.SensorNameConfigExtIEValueIETable, bounds aper.ListBounds) s11.SensorNameConfigExtIEContainerValueCodec {
	if !*s00.BridgeSensorNameConfigExtIEValueIETableFieldBound(&table) {
		return s11.SensorNameConfigExtIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SensorNameConfigExtIEContainerValueCodec {
		sealed := s11.SensorNameConfigExtIEContainerValueCodec{}
		*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorNameConfigExtIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SensorNameConfigExtIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SensorNameConfigExtIEField
					if err := s11.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&sealed) = func(fields s11.SensorNameConfigExtIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSensorNameConfigExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldCapture(&sealed) = func(v s11.SensorNameConfigExtIEContainer, options aper.DecodeState) (s11.SensorNameConfigExtIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldCompare(&sealed) = func(v s11.SensorNameConfigExtIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
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
					if err := s11.BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldCompare(&sealed) = func(v s11.SourceNodeIDExtensionIEIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
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
func ERABSecurityResultListIEValueProtocolErrorIEContainerListCodec(table s00.ERABSecurityResultListIEValueIETable) ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSecurityResultListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSecurityResultListIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABSecurityResultListIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABSecurityResultListIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABSecurityResultListIEContainer(value), fresh, budget)
	}, capture: func(v ERABSecurityResultListIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABSecurityResultListIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSecurityResultListIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABSecurityResultListIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABSecurityResultListIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeSetupItemHOReqIEValueIETable) s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeSetupItemHOReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec{}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList(value), err
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldEncode(&codec))(s29.ERABToBeSetupItemHOReqIEContainer(value), fresh, budget)
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeSwitchedDLItemIEValueIETable) ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeSwitchedDLItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSwitchedDLItemIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeUpdatedItemIEValueIETable) s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeUpdatedItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldEncode(&codec))(s29.ERABToBeUpdatedItemIEContainer(value), fresh, budget)
		}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SensorNameConfigExtIEValueProtocolErrorIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable) s11.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec {
	codec := SensorNameConfigExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s11.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s11.SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec{}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList(value), err
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s11.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
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
func SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable) s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s11.SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList(value), err
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
			f :=
				s.
					Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
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
func ERABSecurityResultListIEValueProtocolIEContainerListCodec(table s00.ERABSecurityResultListIEValueIETable, bounds aper.ListBounds) ERABSecurityResultListIEValueProtocolIEContainerListValueCodec {
	codec := ERABSecurityResultListIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABSecurityResultListIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABSecurityResultListIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSecurityResultListIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABSecurityResultListIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABSecurityResultListIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABSecurityResultListIEContainer(value), fresh, budget)
	}, capture: func(v ERABSecurityResultListIEValueProtocolIEContainerList, options aper.DecodeState) (ERABSecurityResultListIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABSecurityResultListIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABSecurityResultListIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func ERABToBeSetupItemHOReqIEValueProtocolIEContainerListCodec(table s00.ERABToBeSetupItemHOReqIEValueIETable, bounds aper.ListBounds) s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeSetupItemHOReqIEValueIETableCodec(table, bounds)
	if *s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec {
		sealed := s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec{}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, error) {
			value, err := (*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerList(value), err
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldEncode(&codec))(s29.ERABToBeSetupItemHOReqIEContainer(value), fresh, budget)
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, options aper.DecodeState) (s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSwitchedDLItemIEValueProtocolIEContainerListCodec(table s00.ERABToBeSwitchedDLItemIEValueIETable, bounds aper.ListBounds) ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeSwitchedDLItemIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSwitchedDLItemIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSwitchedDLItemIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, options aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func ERABToBeUpdatedItemIEValueProtocolIEContainerListCodec(table s00.ERABToBeUpdatedItemIEValueIETable, bounds aper.ListBounds) s29.ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeUpdatedItemIEValueIETableCodec(table, bounds)
	if *s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s29.ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec {
		sealed := s29.ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec{}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEValueProtocolIEContainerList, error) {
			value, err := (*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s29.ERABToBeUpdatedItemIEValueProtocolIEContainerList(value), err
		}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeUpdatedItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeERABToBeUpdatedItemIEContainerValueCodecFieldEncode(&codec))(s29.ERABToBeUpdatedItemIEContainer(value), fresh, budget)
		}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeUpdatedItemIEValueProtocolIEContainerList, options aper.DecodeState) (s29.ERABToBeUpdatedItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeUpdatedItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SensorNameConfigExtIEValueProtocolIEContainerListCodec(table s00.SensorNameConfigExtIEValueIETable, bounds aper.ListBounds) s11.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec {
	codec := SensorNameConfigExtIEValueIETableCodec(table, bounds)
	if *s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s11.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec {
		sealed := s11.SensorNameConfigExtIEValueProtocolIEContainerListValueCodec{}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SensorNameConfigExtIEValueProtocolIEContainerList, error) {
			value, err := (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s11.SensorNameConfigExtIEValueProtocolIEContainerList(value), err
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.SensorNameConfigExtIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(&codec))(s11.SensorNameConfigExtIEContainer(value), fresh, budget)
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.SensorNameConfigExtIEValueProtocolIEContainerList, options aper.DecodeState) (s11.SensorNameConfigExtIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s11.BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SensorNameConfigExtIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
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
func SourceNodeIDExtensionIEIEValueProtocolIEContainerListCodec(table s00.SourceNodeIDExtensionIEIEValueIETable, bounds aper.ListBounds) s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec {
	codec := SourceNodeIDExtensionIEIEValueIETableCodec(table, bounds)
	if *s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec {
		sealed := s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec{}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, error) {
			value, err := (*s11.BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList(value), err
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
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s11.BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.SourceNodeIDExtensionIEIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSourceNodeIDExtensionIEIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
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

// eRABSecurityResultListIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSecurityResultListIEValue].
type ERABSecurityResultListIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABSecurityResultListIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABSecurityResultListIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEField(v *ERABSecurityResultListIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABSecurityResultListIEValueCompareS1APProtocolIEField(v *ERABSecurityResultListIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABToBeSetupItemHOReqExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s29.ERABToBeSetupItemHOReqExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s29.ERABToBeSetupItemHOReqExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABToBeSetupItemHOReqIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSetupItemHOReqIEValue].
type ERABToBeSetupItemHOReqIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s29.ERABToBeSetupItemHOReqIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s29.ERABToBeSetupItemHOReqIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIEField(v *s29.ERABToBeSetupItemHOReqIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s29.BridgeERABToBeSetupItemHOReqIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s29.BridgeERABToBeSetupItemHOReqIEFieldFieldReplay(v), *s29.BridgeERABToBeSetupItemHOReqIEFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIEField(v *s29.ERABToBeSetupItemHOReqIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s29.BridgeERABToBeSetupItemHOReqIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s29.BridgeERABToBeSetupItemHOReqIEFieldFieldReplay(v), *s29.BridgeERABToBeSetupItemHOReqIEFieldFieldWithoutReplay(v))
}

// eRABToBeSwitchedDLItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSwitchedDLItemExtIEsValue].
type ERABToBeSwitchedDLItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s29.ERABToBeSwitchedDLItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s29.ERABToBeSwitchedDLItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSwitchedDLItemExtIEsValueCaptureS1APProtocolExtensionField(v *s29.ERABToBeSwitchedDLItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s29.BridgeERABToBeSwitchedDLItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldReplay(v), *s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSwitchedDLItemExtIEsValueCompareS1APProtocolExtensionField(v *s29.ERABToBeSwitchedDLItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s29.BridgeERABToBeSwitchedDLItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldReplay(v), *s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldWithoutReplay(v))
}

// eRABToBeSwitchedDLItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSwitchedDLItemIEValue].
type ERABToBeSwitchedDLItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABToBeSwitchedDLItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABToBeSwitchedDLItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIEField(v *ERABToBeSwitchedDLItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIEField(v *ERABToBeSwitchedDLItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABToBeUpdatedItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeUpdatedItemIEValue].
type ERABToBeUpdatedItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s29.ERABToBeUpdatedItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s29.ERABToBeUpdatedItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIEField(v *s29.ERABToBeUpdatedItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s29.BridgeERABToBeUpdatedItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s29.BridgeERABToBeUpdatedItemIEFieldFieldReplay(v), *s29.BridgeERABToBeUpdatedItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIEField(v *s29.ERABToBeUpdatedItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s29.BridgeERABToBeUpdatedItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s29.BridgeERABToBeUpdatedItemIEFieldFieldReplay(v), *s29.BridgeERABToBeUpdatedItemIEFieldFieldWithoutReplay(v))
}

// securityIndicationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SecurityIndicationExtIEsValue].
type SecurityIndicationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.SecurityIndicationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.SecurityIndicationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// securityResultExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SecurityResultExtIEsValue].
type SecurityResultExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.SecurityResultExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.SecurityResultExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSecurityResultExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SecurityResultExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeSecurityResultExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSecurityResultExtIEsExtFieldFieldReplay(v), *s11.BridgeSecurityResultExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSecurityResultExtIEsValueCompareS1APProtocolExtensionField(v *s11.SecurityResultExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeSecurityResultExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSecurityResultExtIEsExtFieldFieldReplay(v), *s11.BridgeSecurityResultExtIEsExtFieldFieldWithoutReplay(v))
}

// sensorMeasConfigNameItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SensorMeasConfigNameItemExtIEsValue].
type SensorMeasConfigNameItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.SensorMeasConfigNameItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.SensorMeasConfigNameItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSensorMeasConfigNameItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SensorMeasConfigNameItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeSensorMeasConfigNameItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldReplay(v), *s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSensorMeasConfigNameItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.SensorMeasConfigNameItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeSensorMeasConfigNameItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldReplay(v), *s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldWithoutReplay(v))
}

// sensorMeasurementConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SensorMeasurementConfigurationExtIEsValue].
type SensorMeasurementConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SensorMeasurementConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SensorMeasurementConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSensorMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SensorMeasurementConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSensorMeasurementConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSensorMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s11.SensorMeasurementConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSensorMeasurementConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
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

func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEField(v *s11.SensorNameConfigExtIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s06.BridgeSensorNameConfigExtIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s11.BridgeSensorNameConfigExtIEFieldFieldReplay(v), *s11.BridgeSensorNameConfigExtIEFieldFieldWithoutReplay(v))
}
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEField(v *s11.SensorNameConfigExtIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSensorNameConfigExtIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s11.BridgeSensorNameConfigExtIEFieldFieldReplay(v), *s11.BridgeSensorNameConfigExtIEFieldFieldWithoutReplay(v))
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

// ERABSecurityResultItemAPERValue is the concrete APERValue[ERABSecurityResultItem].
type ERABSecurityResultItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSecurityResultItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultItemAPERValue) WithoutReplay() ERABSecurityResultItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
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

// ERABSecurityResultListAPERValue is the concrete APERValue[ERABSecurityResultList].
type ERABSecurityResultListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSecurityResultList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultListAPERValue) WithoutReplay() ERABSecurityResultListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedDLItemAPERValue is the concrete APERValue[ERABToBeSwitchedDLItem].
type ERABToBeSwitchedDLItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSwitchedDLItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemAPERValue) WithoutReplay() ERABToBeSwitchedDLItemAPERValue {
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

// ERABToBeSwitchedDLListAPERValue is the concrete APERValue[ERABToBeSwitchedDLList].
type ERABToBeSwitchedDLListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSwitchedDLList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLListAPERValue) WithoutReplay() ERABToBeSwitchedDLListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityResultAPERValue is the concrete APERValue[SecurityResult].
type SecurityResultAPERValue struct {
	context s00.BridgeCodecContext
	Value   SecurityResult

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
func BridgeERABToBeSetupItemHOReqExtIEsValueValidateS1APIEContainer(fields s29.ERABToBeSetupItemHOReqExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s29.BridgeERABToBeSetupItemHOReqExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s29.BridgeERABToBeSetupItemHOReqExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s29.BridgeERABToBeSetupItemHOReqExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeERABToBeSwitchedDLItemExtIEsValueValidateS1APIEContainer(fields s29.ERABToBeSwitchedDLItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s29.BridgeERABToBeSwitchedDLItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s29.BridgeERABToBeSwitchedDLItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s29.BridgeERABToBeSwitchedDLItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSecurityIndicationExtIEsValueValidateS1APIEContainer(fields s11.SecurityIndicationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s05.BridgeSecurityIndicationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s05.BridgeSecurityIndicationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s05.BridgeSecurityIndicationExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSecurityResultExtIEsValueValidateS1APIEContainer(fields s11.SecurityResultExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s05.BridgeSecurityResultExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s05.BridgeSecurityResultExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s05.BridgeSecurityResultExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APIEContainer(fields s11.SensorMeasConfigNameItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s05.BridgeSensorMeasConfigNameItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s05.BridgeSensorMeasConfigNameItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s05.BridgeSensorMeasConfigNameItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APIEContainer(fields s11.SensorMeasurementConfigurationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSensorMeasurementConfigurationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSensorMeasurementConfigurationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSensorMeasurementConfigurationExtIEsValueMethodRule(field.Value).Assignment
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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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

// ConnectionEstablishmentIndicationIEValueERABIEContainerList is the concrete ERABIEContainerList[ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationIEValueERABIEContainerList []ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer

// ERABSecurityResultListIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultListIEValueERABIEContainerList, error)
	encode  func(ERABSecurityResultListIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultListIEValueERABIEContainerList, aper.DecodeState) (ERABSecurityResultListIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABSecurityResultListIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultListIEValueERABIEContainerListValueCodec) New(value ERABSecurityResultListIEValueERABIEContainerList) (ERABSecurityResultListIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultListIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultListIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultListIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultListIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultListIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultListIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultListIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultListIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultListIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultListIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultListIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABSecurityResultListIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultListIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABSecurityResultListIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultListIEValueERABIEContainerListValueCodec) encodeChanged(value ERABSecurityResultListIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSecurityResultListIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABSecurityResultListIEValue].
type ERABSecurityResultListIEValueERABIEContainerList []ERABSecurityResultListIEValueProtocolIESingleContainer

func BridgeERABSecurityResultListIEValueCaptureS1APERABIEContainerList(v *ERABSecurityResultListIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSecurityResultListIEValueCompareS1APERABIEContainerList(v *ERABSecurityResultListIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSetupItemHOReqIEValueCaptureS1APERABIEContainerList(v *s29.ERABToBeSetupItemHOReqIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemHOReqIEValueCompareS1APERABIEContainerList(v *s29.ERABToBeSetupItemHOReqIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueERABIEContainerList, error)
	encode  func(ERABToBeSwitchedDLItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLItemIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABToBeSwitchedDLItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) New(value ERABToBeSwitchedDLItemIEValueERABIEContainerList) (ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) encodeChanged(value ERABToBeSwitchedDLItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedDLItemIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABToBeSwitchedDLItemIEValue].
type ERABToBeSwitchedDLItemIEValueERABIEContainerList []ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer

func BridgeERABToBeSwitchedDLItemIEValueCaptureS1APERABIEContainerList(v *ERABToBeSwitchedDLItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedDLItemIEValueCompareS1APERABIEContainerList(v *ERABToBeSwitchedDLItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeUpdatedItemIEValueCaptureS1APERABIEContainerList(v *s29.ERABToBeUpdatedItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeUpdatedItemIEValueCompareS1APERABIEContainerList(v *s29.ERABToBeUpdatedItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APERABIEContainerList(v *s11.SensorNameConfigExtIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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

// ConnectionEstablishmentIndicationIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ConnectionEstablishmentIndicationIEValue]].
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

// ERABSecurityResultListIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultListIEField, error)
	encode  func(ERABSecurityResultListIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultListIEField, aper.DecodeState) (ERABSecurityResultListIEField, aper.Snapshot)
	compare func(ERABSecurityResultListIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultListIEFieldValueCodec) New(value ERABSecurityResultListIEField) (ERABSecurityResultListIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultListIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultListIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultListIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultListIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultListIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultListIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultListIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultListIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultListIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultListIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultListIEFieldValueCodec) EncodeAPER(value ERABSecurityResultListIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultListIEFieldValueCodec) encodeBudgetValue(value ERABSecurityResultListIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultListIEFieldValueCodec) encodeChanged(value ERABSecurityResultListIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedDLItemIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEField, error)
	encode  func(ERABToBeSwitchedDLItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLItemIEField, aper.DecodeState) (ERABToBeSwitchedDLItemIEField, aper.Snapshot)
	compare func(ERABToBeSwitchedDLItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLItemIEFieldValueCodec) New(value ERABToBeSwitchedDLItemIEField) (ERABToBeSwitchedDLItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLItemIEFieldValueCodec) EncodeAPER(value ERABToBeSwitchedDLItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLItemIEFieldValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLItemIEFieldValueCodec) encodeChanged(value ERABToBeSwitchedDLItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// ConnectionEstablishmentIndicationIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ConnectionEstablishmentIndicationIEValue]].
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

// ERABSecurityResultListIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultListIEContainer, error)
	encode  func(ERABSecurityResultListIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultListIEContainer, aper.DecodeState) (ERABSecurityResultListIEContainer, aper.Snapshot)
	compare func(ERABSecurityResultListIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultListIEContainerValueCodec) New(value ERABSecurityResultListIEContainer) (ERABSecurityResultListIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultListIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultListIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultListIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultListIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultListIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultListIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultListIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultListIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultListIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultListIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultListIEContainerValueCodec) EncodeAPER(value ERABSecurityResultListIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultListIEContainerValueCodec) encodeBudgetValue(value ERABSecurityResultListIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultListIEContainerValueCodec) encodeChanged(value ERABSecurityResultListIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEContainer(v *ERABSecurityResultListIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSecurityResultListIEValueCompareS1APProtocolIEContainer(v *ERABSecurityResultListIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIEContainer(v *s29.ERABToBeSetupItemHOReqIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIEContainer(v *s29.ERABToBeSetupItemHOReqIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSwitchedDLItemIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEContainer, error)
	encode  func(ERABToBeSwitchedDLItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLItemIEContainer, aper.DecodeState) (ERABToBeSwitchedDLItemIEContainer, aper.Snapshot)
	compare func(ERABToBeSwitchedDLItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLItemIEContainerValueCodec) New(value ERABToBeSwitchedDLItemIEContainer) (ERABToBeSwitchedDLItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLItemIEContainerValueCodec) EncodeAPER(value ERABToBeSwitchedDLItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLItemIEContainerValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLItemIEContainerValueCodec) encodeChanged(value ERABToBeSwitchedDLItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIEContainer(v *ERABToBeSwitchedDLItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIEContainer(v *ERABToBeSwitchedDLItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIEContainer(v *s29.ERABToBeUpdatedItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIEContainer(v *s29.ERABToBeUpdatedItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainer(v *s11.SensorNameConfigExtIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeSensorNameConfigExtIEValueCompareS1APProtocolIEContainer(v *s11.SensorNameConfigExtIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultListIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABSecurityResultListIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultListIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSecurityResultListIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABSecurityResultListIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) New(value ERABSecurityResultListIEValueProtocolErrorIEContainerList) (ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABSecurityResultListIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABSecurityResultListIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSecurityResultListIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABSecurityResultListIEValue].
type ERABSecurityResultListIEValueProtocolErrorIEContainerList []ERABSecurityResultListIEValueProtocolIESingleContainer

func BridgeERABSecurityResultListIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABSecurityResultListIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSecurityResultListIEValueCompareS1APProtocolErrorIEContainerList(v *ERABSecurityResultListIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolErrorIEContainerList(v *s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolErrorIEContainerList(v *s29.ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) New(value ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList) (ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABToBeSwitchedDLItemIEValue].
type ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList []ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer

func BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolErrorIEContainerList(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolErrorIEContainerList(v *s29.ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolErrorIEContainerList(v *s11.SensorNameConfigExtIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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

// ERABSecurityResultListIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultListIEValueProtocolIEContainerList, error)
	encode  func(ERABSecurityResultListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultListIEValueProtocolIEContainerList, aper.DecodeState) (ERABSecurityResultListIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABSecurityResultListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) New(value ERABSecurityResultListIEValueProtocolIEContainerList) (ERABSecurityResultListIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultListIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultListIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABSecurityResultListIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABSecurityResultListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABSecurityResultListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSecurityResultListIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABSecurityResultListIEValue].
type ERABSecurityResultListIEValueProtocolIEContainerList []ERABSecurityResultListIEValueProtocolIESingleContainer

func BridgeERABSecurityResultListIEValueCaptureS1APProtocolIEContainerList(v *ERABSecurityResultListIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSecurityResultListIEValueCompareS1APProtocolIEContainerList(v *ERABSecurityResultListIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIEContainerList(v *s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIEContainerList(v *s29.ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, error)
	encode  func(ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) New(value ERABToBeSwitchedDLItemIEValueProtocolIEContainerList) (ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedDLItemIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABToBeSwitchedDLItemIEValue].
type ERABToBeSwitchedDLItemIEValueProtocolIEContainerList []ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer

func BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIEContainerList(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIEContainerList(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIEContainerList(v *s29.ERABToBeUpdatedItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIEContainerList(v *s29.ERABToBeUpdatedItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSensorNameConfigExtIEValueCaptureS1APProtocolIEContainerList(v *s11.SensorNameConfigExtIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
			BridgeSensorNameConfigExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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

// ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ConnectionEstablishmentIndicationIEValue]].
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

// ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer = ConnectionEstablishmentIndicationIEField

// ERABSecurityResultListIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSecurityResultListIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultListIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultListIEValueERABIEContainerListAPERValue) WithoutReplay() ERABSecurityResultListIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedDLItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue) WithoutReplay() ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
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

// ConnectionEstablishmentIndicationIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ConnectionEstablishmentIndicationIEValue]].
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

// ERABSecurityResultListIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSecurityResultListIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultListIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultListIEFieldAPERValue) WithoutReplay() ERABSecurityResultListIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedDLItemIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedDLItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemIEFieldAPERValue) WithoutReplay() ERABToBeSwitchedDLItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ConnectionEstablishmentIndicationIEValue]].
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

// ERABSecurityResultListIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSecurityResultListIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultListIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultListIEContainerAPERValue) WithoutReplay() ERABSecurityResultListIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedDLItemIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedDLItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemIEContainerAPERValue) WithoutReplay() ERABToBeSwitchedDLItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSecurityResultListIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSecurityResultListIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABSecurityResultListIEValue]].
type ERABSecurityResultListIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSecurityResultListIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultListIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultListIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABSecurityResultListIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABToBeSwitchedDLItemIEValue]].
type ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedDLItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue {
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
func BridgeCaptureS1APERABSecurityResultItem(v *ERABSecurityResultItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	BridgeCaptureS1APSecurityResult(&v.SecurityResult, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSecurityResultItem(v *ERABSecurityResultItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	BridgeCompareS1APSecurityResult(&v.SecurityResult, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSecurityResultList(v *ERABSecurityResultList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABSecurityResultList(v *ERABSecurityResultList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABSecurityResultListIEValue(v *ERABSecurityResultListIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(334):
			{
				f := s.Begin()
				s.Bool(v.rowERABSecurityResultItem == nil)
				if v.rowERABSecurityResultItem != nil {
					BridgeCaptureS1APERABSecurityResultItem(v.rowERABSecurityResultItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSecurityResultListIEValue) captureSemantics(s aper.SemanticCapture) ERABSecurityResultListIEValue {
	BridgeCaptureS1APERABSecurityResultListIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABSecurityResultListIEValue(v *ERABSecurityResultListIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(334):
			{
				f := s.Begin()
				s.Bool(v.rowERABSecurityResultItem == nil)
				if v.rowERABSecurityResultItem != nil {
					BridgeCompareS1APERABSecurityResultItem(v.rowERABSecurityResultItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSecurityResultListIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABSecurityResultListIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupListHOReq(v *s29.ERABToBeSetupListHOReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABToBeSetupListHOReq(v *s29.ERABToBeSetupListHOReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABToBeSwitchedDLItem(v *ERABToBeSwitchedDLItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.GTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSwitchedDLItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSwitchedDLItem(v *ERABToBeSwitchedDLItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSwitchedDLItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSwitchedDLItemIEValue(v *ERABToBeSwitchedDLItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(23):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedDLItem == nil)
				if v.rowERABToBeSwitchedDLItem != nil {
					BridgeCaptureS1APERABToBeSwitchedDLItem(v.rowERABToBeSwitchedDLItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSwitchedDLItemIEValue) captureSemantics(s aper.SemanticCapture) ERABToBeSwitchedDLItemIEValue {
	BridgeCaptureS1APERABToBeSwitchedDLItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSwitchedDLItemIEValue(v *ERABToBeSwitchedDLItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(23):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedDLItem == nil)
				if v.rowERABToBeSwitchedDLItem != nil {
					BridgeCompareS1APERABToBeSwitchedDLItem(v.rowERABToBeSwitchedDLItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSwitchedDLItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSwitchedDLItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSwitchedDLList(v *ERABToBeSwitchedDLList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABToBeSwitchedDLList(v *ERABToBeSwitchedDLList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedDLItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABToBeUpdatedList(v *s29.ERABToBeUpdatedList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABToBeUpdatedList(v *s29.ERABToBeUpdatedList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeUpdatedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSecurityResult(v *SecurityResult, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APIntegrityProtectionResult(&v.IntegrityProtectionResult, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecurityResultExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSecurityResult(v *SecurityResult, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APIntegrityProtectionResult(&v.IntegrityProtectionResult, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecurityResultExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
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
	s07.BridgeCompareS1APSensorMeasConfig(&v.SensorMeasConfig, s)
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
type ERABSecurityResultList = []ERABSecurityResultListIEValueProtocolIESingleContainer

// ERABSecurityResultItem represents the ASN.1 type E-RABSecurityResultItem (SEQUENCE).
type ERABSecurityResultItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                   `asn1:"tag:0,context,implicit"`
	SecurityResult    SecurityResult                               `asn1:"tag:1,context,implicit"`
	IEExtensions      s08.ERABSecurityResultItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                         `asn1:"-" json:"-"`
	extCount          int64                                        `asn1:"-" json:"-"`
	extPresent        []bool                                       `asn1:"-" json:"-"`
	extData           [][]byte                                     `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// SecurityResult represents the ASN.1 type SecurityResult (SEQUENCE).
type SecurityResult struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	IntegrityProtectionResult s00.IntegrityProtectionResult        `asn1:"tag:0,context,implicit"`
	IEExtensions              s11.SecurityResultExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                 `asn1:"-" json:"-"`
	extCount                  int64                                `asn1:"-" json:"-"`
	extPresent                []bool                               `asn1:"-" json:"-"`
	extData                   [][]byte                             `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
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
	ChoiceExtensions              *s11.SensorNameConfigExtIEValueProtocolIESingleContainer `json:"ChoiceExtensions,omitempty"`
}

// NewSensorNameConfigUncompensatedBarometricConfig creates a SensorNameConfig with the uncompensatedBarometricConfig alternative.
func BridgeNewSensorNameConfigUncompensatedBarometricConfigLegacy(v int64) SensorNameConfig {
	return SensorNameConfig{
		Choice:                        s00.SensorNameConfigChoiceUncompensatedBarometricConfig,
		UncompensatedBarometricConfig: &v,
	}
}

// NewSensorNameConfigChoiceExtensions creates a SensorNameConfig with the choice-Extensions alternative.
func BridgeNewSensorNameConfigChoiceExtensionsLegacy(v s11.SensorNameConfigExtIEValueProtocolIESingleContainer) SensorNameConfig {
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
		tmp_ieextensions := make(s11.ServedDCNsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.ServedDCNsItemExtIEsExtField
				if err := s11.BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABInformationListTo appends a ERABInformationList list to bb.
func BridgeMarshalAPERERABInformationListTo(list s29.ERABInformationList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s29.BridgeAsn1cAPERERABInformationListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s29.BridgeERABInformationListIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

type BridgeAsn1cAPERERABSecurityResultListListValue struct{ Value ERABSecurityResultList }

// MarshalAPERERABSecurityResultListTo appends a ERABSecurityResultList list to bb.
func BridgeMarshalAPERERABSecurityResultListTo(list ERABSecurityResultList, bb *aper.BitBuffer, fresh ...bool) error {
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

// MarshalAPER encodes ERABSecurityResultItem to APER format.
func (v *ERABSecurityResultItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABSecurityResultItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.SecurityResult.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding securityResult: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABSecurityResultItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABSecurityResultItem from APER format.
func (v *ERABSecurityResultItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABSecurityResultItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABSecurityResultItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSecurityResultItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSecurityResultItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSecurityResultItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSecurityResultItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABSecurityResultItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSecurityResultItem{}
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
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	toleranceMark_securityresult := bb.EnterComponent("SecurityResult")
	if err := v.SecurityResult.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecurityResult")
	}
	bb.LeaveComponent(toleranceMark_securityresult)
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ERABSecurityResultItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABSecurityResultItemExtIEsExtField
				if err := s08.BridgeERABSecurityResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SecurityResult to APER format.
func (v *SecurityResult) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SecurityResult) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.IntegrityProtectionResult), 2, true); err != nil {
		return fmt.Errorf("encoding integrityProtectionResult: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSecurityResultExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SecurityResult from APER format.
func (v *SecurityResult) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SecurityResult with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SecurityResult) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SecurityResult")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecurityResult")
	}
	padding, err := aper.CaptureFinalBits(bb, "SecurityResult")
	if err != nil {
		return runtime.WrapDecodePath(err, "SecurityResult")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SecurityResult) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityResult{}
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
	val_integrityprotectionresult, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IntegrityProtectionResult"})
	if err != nil {
		return runtime.WrapDecodePath(err, "IntegrityProtectionResult")
	}
	v.IntegrityProtectionResult = s00.IntegrityProtectionResult(val_integrityprotectionresult)
	if opt_ieextensions {
		tmp_ieextensions := make(s11.SecurityResultExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SecurityResultExtIEsExtField
				if err := s11.BridgeSecurityResultExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := v.SensorNameConfig.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SensorNameConfig")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.SensorMeasConfigNameItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SensorMeasConfigNameItemExtIEsExtField
				if err := s11.BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		tmp_ieextensions := make(s11.SensorMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SensorMeasurementConfigurationExtIEsExtField
				if err := s11.BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		if err := s11.BridgeSensorNameConfigExtIEFieldMethodMarshalAPERTo(v.ChoiceExtensions, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPERWithOptions decodes SensorNameConfig with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SensorNameConfig) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SensorNameConfig")
	}
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
		var dec_choiceextensions s11.SensorNameConfigExtIEValueProtocolIESingleContainer
		if err := s11.BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(&dec_choiceextensions, bb); err != nil {
			return runtime.WrapDecodePath(err, "ChoiceExtensions")
		}
		if err := aper.ChargeValue(bb, dec_choiceextensions); err != nil {
			return err
		}
		v.ChoiceExtensions = &dec_choiceextensions
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
		var dec_sourcenodeidextension s20.SourceNodeIDExtension
		if err := s20.BridgeSourceNodeIDExtensionMethodUnmarshalAPERFrom(&dec_sourcenodeidextension, bb); err != nil {
			return runtime.WrapDecodePath(err, "SourceNodeIDExtension")
		}
		if err := aper.ChargeValue(bb, dec_sourcenodeidextension); err != nil {
			return err
		}
		v.SourceNodeIDExtension = &dec_sourcenodeidextension
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
		tmp_ieextensions := make(s11.SourceNgRanNodeIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SourceNgRanNodeIDExtIEsExtField
				if err := s11.BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if opt_ieextensions {
		tmp_ieextensions := make(s11.ServedGUMMEIsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.ServedGUMMEIsItemExtIEsExtField
				if err := s11.BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		tmp_ieextensions := make(s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField
				if err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ERABSecurityResultItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSecurityResultItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSecurityResultItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSecurityResultItem) WithoutReplay() ERABSecurityResultItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSecurityResultItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SecurityResult) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SecurityResult", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SecurityResult", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SecurityResult) WithoutReplay() SecurityResult {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SecurityResult
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
func (v *SensorNameConfig) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SensorNameConfig", v.receivedLocation, v.perPadding)
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

// Extensions returns owned unknown sequence additions.
func (v *ERABSecurityResultItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABSecurityResultItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSecurityResultItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSecurityResultItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABSecurityResultItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSecurityResultItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSecurityResultItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SecurityResult) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SecurityResult) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecurityResult.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecurityResult.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SecurityResult) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecurityResult.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecurityResult.Extensions[%d]", index))
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABSecurityResultItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSecurityResultItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSecurityResultItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSecurityResultItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSecurityResultItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSecurityResultItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSecurityResultItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSecurityResultItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSecurityResultItem")
}
func (v *ERABSecurityResultItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSecurityResultItem")
}
func (v *ERABSecurityResultItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSecurityResultItem(v, &s)
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
func (v *ERABSecurityResultItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSecurityResultItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SecurityResult) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SecurityResult")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SecurityResult) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SecurityResult")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSecurityResult(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SecurityResult")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SecurityResult")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SecurityResult) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SecurityResult")
}
func (v *SecurityResult) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SecurityResult")
}
func (v *SecurityResult) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSecurityResult(v, &s)
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
func (v *SecurityResult) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SecurityResult) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABSecurityResultItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSecurityResultItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSecurityResultItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSecurityResultItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSecurityResultItem{}
		return report, aper.OperationError(err, "ERABSecurityResultItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSecurityResultItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SecurityResult) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SecurityResult")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SecurityResult
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSecurityResult(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SecurityResult{}
		return report, aper.OperationError(err, "SecurityResult")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SecurityResult")
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
func NewSensorNameConfigChoiceExtensions(v s11.SensorNameConfigExtIEValueProtocolIESingleContainer, options ...aper.BuildOption) (SensorNameConfig, error) {
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

type ERABToBeSwitchedDLList = []ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer

// ERABToBeSwitchedDLItem represents the ASN.1 type E-RABToBeSwitchedDLItem (SEQUENCE).
type ERABToBeSwitchedDLItem struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	ERABID                s00.ERABID                                   `asn1:"tag:0,context,implicit"`
	TransportLayerAddress s00.TransportLayerAddress                    `asn1:"tag:1,context,implicit"`
	GTPTEID               s00.GTPTEID                                  `asn1:"tag:2,context,implicit"`
	IEExtensions          s29.ERABToBeSwitchedDLItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                         `asn1:"-" json:"-"`
	extCount              int64                                        `asn1:"-" json:"-"`
	extPresent            []bool                                       `asn1:"-" json:"-"`
	extData               [][]byte                                     `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}
type BridgeAsn1cAPERERABToBeSetupListHOReqListValue struct{ Value s29.ERABToBeSetupListHOReq }

// MarshalAPERERABToBeSetupListHOReqTo appends a ERABToBeSetupListHOReq list to bb.
func BridgeMarshalAPERERABToBeSetupListHOReqTo(list s29.ERABToBeSetupListHOReq, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERERABToBeSetupListHOReqListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s29.BridgeERABToBeSetupItemHOReqIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

type BridgeAsn1cAPERERABToBeSwitchedDLListListValue struct{ Value ERABToBeSwitchedDLList }

// MarshalAPERERABToBeSwitchedDLListTo appends a ERABToBeSwitchedDLList list to bb.
func BridgeMarshalAPERERABToBeSwitchedDLListTo(list ERABToBeSwitchedDLList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERERABToBeSwitchedDLListListValue{Value: list}
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

// MarshalAPER encodes ERABToBeSwitchedDLItem to APER format.
func (v *ERABToBeSwitchedDLItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABToBeSwitchedDLItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeSwitchedDLItem from APER format.
func (v *ERABToBeSwitchedDLItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSwitchedDLItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSwitchedDLItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedDLItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedDLItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedDLItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedDLItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABToBeSwitchedDLItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSwitchedDLItem{}
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
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = s00.GTPTEID(val_gtpteid)
	if opt_ieextensions {
		tmp_ieextensions := make(s29.ERABToBeSwitchedDLItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s29.ERABToBeSwitchedDLItemExtIEsExtField
				if err := s29.BridgeERABToBeSwitchedDLItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABToBeUpdatedListTo appends a ERABToBeUpdatedList list to bb.
func BridgeMarshalAPERERABToBeUpdatedListTo(list s29.ERABToBeUpdatedList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s29.BridgeAsn1cAPERERABToBeUpdatedListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s29.BridgeERABToBeUpdatedItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABToBeSetupListBearerSUReqTo appends a ERABToBeSetupListBearerSUReq list to bb.
func BridgeMarshalAPERERABToBeSetupListBearerSUReqTo(list s29.ERABToBeSetupListBearerSUReq, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s29.BridgeAsn1cAPERERABToBeSetupListBearerSUReqListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s29.BridgeERABToBeSetupItemBearerSUReqIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABToBeSetupListCtxtSUReqTo appends a ERABToBeSetupListCtxtSUReq list to bb.
func BridgeMarshalAPERERABToBeSetupListCtxtSUReqTo(list s29.ERABToBeSetupListCtxtSUReq, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s29.BridgeAsn1cAPERERABToBeSetupListCtxtSUReqListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s29.BridgeERABToBeSetupItemCtxtSUReqIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeSwitchedDLItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSwitchedDLItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSwitchedDLItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSwitchedDLItem) WithoutReplay() ERABToBeSwitchedDLItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSwitchedDLItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABToBeSwitchedDLItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABToBeSwitchedDLItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSwitchedDLItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSwitchedDLItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABToBeSwitchedDLItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSwitchedDLItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSwitchedDLItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeSwitchedDLItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSwitchedDLItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSwitchedDLItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSwitchedDLItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSwitchedDLItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSwitchedDLItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSwitchedDLItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSwitchedDLItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSwitchedDLItem")
}
func (v *ERABToBeSwitchedDLItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSwitchedDLItem")
}
func (v *ERABToBeSwitchedDLItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSwitchedDLItem(v, &s)
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
func (v *ERABToBeSwitchedDLItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSwitchedDLItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeSwitchedDLItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSwitchedDLItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSwitchedDLItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSwitchedDLItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSwitchedDLItem{}
		return report, aper.OperationError(err, "ERABToBeSwitchedDLItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSwitchedDLItem")
}

type ERABSecurityResultListIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowERABSecurityResultItem *ERABSecurityResultItem
}

func (v ERABSecurityResultListIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(334):
		return v.rowERABSecurityResultItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABSecurityResultListIEValue and reports whether the opaque alternative is selected.
func (v *ERABSecurityResultListIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABSecurityResultListIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABSecurityResultListIEs"}}
}
func (ERABSecurityResultListIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(334):
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

// AsERABSecurityResultItem returns the selected ERABSecurityResultItem value of ERABSecurityResultListIEValue and reports whether that alternative is active.
func (v *ERABSecurityResultListIEValue) AsERABSecurityResultItem() (*ERABSecurityResultItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(334) || v.rowERABSecurityResultItem == nil {
		return nil, false
	}
	return v.rowERABSecurityResultItem, true
}
func (v ERABSecurityResultListIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABSecurityResultListIEValue, error) {
	out := ERABSecurityResultListIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(334):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABSecurityResultItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABSecurityResultItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABSecurityResultItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABSecurityResultItem = &value
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
func (v ERABSecurityResultListIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABSecurityResultListIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(334):
		if v.rowERABSecurityResultItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSecurityResultListIEs.id-E-RABSecurityResultItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABSecurityResultItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABSecurityResultListIEValue:", v.id)
	}
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

type ERABToBeSwitchedDLItemIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowERABToBeSwitchedDLItem *ERABToBeSwitchedDLItem
}

func (v ERABToBeSwitchedDLItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(23):
		return v.rowERABToBeSwitchedDLItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSwitchedDLItemIEValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSwitchedDLItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSwitchedDLItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedDLItemIEs"}}
}
func (ERABToBeSwitchedDLItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(23):
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

// AsERABToBeSwitchedDLItem returns the selected ERABToBeSwitchedDLItem value of ERABToBeSwitchedDLItemIEValue and reports whether that alternative is active.
func (v *ERABToBeSwitchedDLItemIEValue) AsERABToBeSwitchedDLItem() (*ERABToBeSwitchedDLItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(23) || v.rowERABToBeSwitchedDLItem == nil {
		return nil, false
	}
	return v.rowERABToBeSwitchedDLItem, true
}
func (v ERABToBeSwitchedDLItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSwitchedDLItemIEValue, error) {
	out := ERABToBeSwitchedDLItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(23):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABToBeSwitchedDLItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSwitchedDLItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABToBeSwitchedDLItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABToBeSwitchedDLItem = &value
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
func (v ERABToBeSwitchedDLItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABToBeSwitchedDLItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(23):
		if v.rowERABToBeSwitchedDLItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSwitchedDLItemIEs.id-E-RABToBeSwitchedDLItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABToBeSwitchedDLItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSwitchedDLItemIEValue:", v.id)
	}
}

type ERABSecurityResultListIETable struct{}

func ERABSecurityResultListIEs() ERABSecurityResultListIETable {
	return ERABSecurityResultListIETable{}
}

// ID returns the ASN.1 object-set identity of ERABSecurityResultListIETable.
func (ERABSecurityResultListIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABSecurityResultListIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABSecurityResultListIETable.
func (ERABSecurityResultListIETable) Table() s00.ERABSecurityResultListIEValueIETable {
	return func() s00.ERABSecurityResultListIEValueIETable {
		sealed := s00.ERABSecurityResultListIEValueIETable{}
		*s00.BridgeERABSecurityResultListIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABSecurityResultListIETable) infoERABSecurityResultItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSecurityResultListIEs().ID(), ID: s00.ProtocolIEID(334), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABSecurityResultItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABSecurityResultListIEs", Row: "id-E-RABSecurityResultItem"}}}
}

// ERABSecurityResultItem returns the typed binding for the ERABSecurityResultItem row of ERABSecurityResultListIETable.
func (t ERABSecurityResultListIETable) ERABSecurityResultItem() ERABSecurityResultListERABSecurityResultItemIEBinding {
	return ERABSecurityResultListERABSecurityResultItemIEBinding{info: t.infoERABSecurityResultItem(), codec: ERABSecurityResultItemValueCodec{path: "ERABSecurityResultItem",
		decode: func(data []byte, options aper.DecodeState) (ERABSecurityResultItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABSecurityResultItem
				return empty, err
			}
			var zero ERABSecurityResultListIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(334), raw)
			if err != nil {
				var empty ERABSecurityResultItem
				return empty, err
			}
			value, ok := decoded.AsERABSecurityResultItem()
			if !ok {
				var empty ERABSecurityResultItem
				return empty, fmt.Errorf("binding E-RABSecurityResultListIEs.id-E-RABSecurityResultItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABSecurityResultItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSecurityResultListIEValue{id: s00.ProtocolIEID(334), rowERABSecurityResultItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABSecurityResultItem, options aper.DecodeState) (ERABSecurityResultItem, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABSecurityResultItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABSecurityResultItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABSecurityResultItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSecurityResultItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABSecurityResultItem) ERABSecurityResultListIEValue {
		return ERABSecurityResultListIEValue{id: s00.ProtocolIEID(334), rowERABSecurityResultItem: &value}
	}, get: func(value *ERABSecurityResultListIEValue) (*ERABSecurityResultItem, bool) {
		return value.AsERABSecurityResultItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABSecurityResultListIETable.
func (t ERABSecurityResultListIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABSecurityResultListIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABSecurityResultListIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(334):
		return ERABSecurityResultListIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABSecurityResultItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABSecurityResultListIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABSecurityResultListIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABSecurityResultListIEField{Id: id, Criticality: criticality, Value: ERABSecurityResultListIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSwitchedDLItemIETable struct{}

func ERABToBeSwitchedDLItemIEs() ERABToBeSwitchedDLItemIETable {
	return ERABToBeSwitchedDLItemIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSwitchedDLItemIETable.
func (ERABToBeSwitchedDLItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedDLItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSwitchedDLItemIETable.
func (ERABToBeSwitchedDLItemIETable) Table() s00.ERABToBeSwitchedDLItemIEValueIETable {
	return func() s00.ERABToBeSwitchedDLItemIEValueIETable {
		sealed := s00.ERABToBeSwitchedDLItemIEValueIETable{}
		*s00.BridgeERABToBeSwitchedDLItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeSwitchedDLItemIETable) infoERABToBeSwitchedDLItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABToBeSwitchedDLItemIEs().ID(), ID: s00.ProtocolIEID(23), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedDLItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedDLItemIEs", Row: "id-E-RABToBeSwitchedDLItem"}}}
}

// ERABToBeSwitchedDLItem returns the typed binding for the ERABToBeSwitchedDLItem row of ERABToBeSwitchedDLItemIETable.
func (t ERABToBeSwitchedDLItemIETable) ERABToBeSwitchedDLItem() ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding {
	return ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding{info: t.infoERABToBeSwitchedDLItem(), codec: ERABToBeSwitchedDLItemValueCodec{path: "ERABToBeSwitchedDLItem",
		decode: func(data []byte, options aper.DecodeState) (ERABToBeSwitchedDLItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABToBeSwitchedDLItem
				return empty, err
			}
			var zero ERABToBeSwitchedDLItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(23), raw)
			if err != nil {
				var empty ERABToBeSwitchedDLItem
				return empty, err
			}
			value, ok := decoded.AsERABToBeSwitchedDLItem()
			if !ok {
				var empty ERABToBeSwitchedDLItem
				return empty, fmt.Errorf("binding E-RABToBeSwitchedDLItemIEs.id-E-RABToBeSwitchedDLItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABToBeSwitchedDLItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSwitchedDLItemIEValue{id: s00.ProtocolIEID(23), rowERABToBeSwitchedDLItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABToBeSwitchedDLItem, options aper.DecodeState) (ERABToBeSwitchedDLItem, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABToBeSwitchedDLItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSwitchedDLItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABToBeSwitchedDLItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSwitchedDLItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABToBeSwitchedDLItem) ERABToBeSwitchedDLItemIEValue {
		return ERABToBeSwitchedDLItemIEValue{id: s00.ProtocolIEID(23), rowERABToBeSwitchedDLItem: &value}
	}, get: func(value *ERABToBeSwitchedDLItemIEValue) (*ERABToBeSwitchedDLItem, bool) {
		return value.AsERABToBeSwitchedDLItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSwitchedDLItemIETable.
func (t ERABToBeSwitchedDLItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABToBeSwitchedDLItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSwitchedDLItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(23):
		return ERABToBeSwitchedDLItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSwitchedDLItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSwitchedDLItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSwitchedDLItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSwitchedDLItemIEField{Id: id, Criticality: criticality, Value: ERABToBeSwitchedDLItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ERABSecurityResultItemCodec binds the complete APER value type.
func ERABSecurityResultItemCodec() ERABSecurityResultItemValueCodec {
	return ERABSecurityResultListIEs().ERABSecurityResultItem().Codec()
}

// ERABToBeSwitchedDLItemCodec binds the complete APER value type.
func ERABToBeSwitchedDLItemCodec() ERABToBeSwitchedDLItemValueCodec {
	return ERABToBeSwitchedDLItemIEs().ERABToBeSwitchedDLItem().Codec()
}

// SecurityResultCodec binds the complete source value type.
func SecurityResultCodec() SecurityResultValueCodec {
	return SecurityResultValueCodec{path: "SecurityResult", decode: func(data []byte, options aper.DecodeState) (SecurityResult, error) {
		var value SecurityResult
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SecurityResult{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SecurityResult, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SecurityResult, options aper.DecodeState) (SecurityResult, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSecurityResult(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SecurityResult, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSecurityResult(&v, &s)
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
func BridgeERABSecurityResultItemAPERValueFieldContext(v *ERABSecurityResultItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultItemAPERValueFieldReceived(v *ERABSecurityResultItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSecurityResultItemAPERValueFieldReplay(v *ERABSecurityResultItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultItemAPERValueFieldWithoutReplay(v *ERABSecurityResultItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultItemFieldExtCount(v *ERABSecurityResultItem) *int64   { return &v.extCount }
func BridgeERABSecurityResultItemFieldExtData(v *ERABSecurityResultItem) *[][]byte { return &v.extData }
func BridgeERABSecurityResultItemFieldExtOrigin(v *ERABSecurityResultItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABSecurityResultItemFieldExtPresent(v *ERABSecurityResultItem) *[]bool {
	return &v.extPresent
}
func BridgeERABSecurityResultItemFieldExtWire(v *ERABSecurityResultItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABSecurityResultItemFieldIEExtensionsIndef(v *ERABSecurityResultItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABSecurityResultItemFieldPerExtPadding(v *ERABSecurityResultItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABSecurityResultItemFieldPerPadding(v *ERABSecurityResultItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABSecurityResultItemFieldReceived(v *ERABSecurityResultItem) *bool { return &v.received }
func BridgeERABSecurityResultItemFieldReceivedAbsolute(v *ERABSecurityResultItem) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSecurityResultItemFieldReceivedBytes(v *ERABSecurityResultItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSecurityResultItemFieldReceivedLocation(v *ERABSecurityResultItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSecurityResultItemFieldReplay(v *ERABSecurityResultItem) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultItemFieldStream(v *ERABSecurityResultItem) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSecurityResultItemFieldWithoutReplay(v *ERABSecurityResultItem) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultItemMethodMarshalAPERBudget(v *ERABSecurityResultItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSecurityResultItemMethodMarshalAPERBudgetValue(v *ERABSecurityResultItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABSecurityResultItemMethodMarshalAPERChanged(v *ERABSecurityResultItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABSecurityResultItemMethodMarshalAPERChangedValue(v *ERABSecurityResultItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABSecurityResultItemMethodMarshalAPERLegacy(v *ERABSecurityResultItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABSecurityResultItemMethodMarshalAPERNewValue(v *ERABSecurityResultItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABSecurityResultItemMethodMarshalAPERPlanned(v *ERABSecurityResultItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABSecurityResultItemMethodMarshalAPERTo(v *ERABSecurityResultItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSecurityResultItemMethodUnmarshalAPERFrom(v *ERABSecurityResultItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSecurityResultItemMethodUnmarshalAPERLegacy(v *ERABSecurityResultItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABSecurityResultItemMethodUnmarshalAPERWithOptions(v *ERABSecurityResultItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSecurityResultItemValueCodecFieldCapture(v *ERABSecurityResultItemValueCodec) *func(ERABSecurityResultItem, aper.DecodeState) (ERABSecurityResultItem, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultItemValueCodecFieldCompare(v *ERABSecurityResultItemValueCodec) *func(ERABSecurityResultItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultItemValueCodecFieldContext(v *ERABSecurityResultItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultItemValueCodecFieldDecode(v *ERABSecurityResultItemValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultItem, error) {
	return &v.decode
}
func BridgeERABSecurityResultItemValueCodecFieldEncode(v *ERABSecurityResultItemValueCodec) *func(ERABSecurityResultItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultItemValueCodecFieldPath(v *ERABSecurityResultItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultItemValueCodecMethodEncodeBudgetValue(v ERABSecurityResultItemValueCodec, a0 ERABSecurityResultItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSecurityResultItemValueCodecMethodEncodeChanged(v ERABSecurityResultItemValueCodec, a0 ERABSecurityResultItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSecurityResultListAPERValueFieldContext(v *ERABSecurityResultListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListAPERValueFieldReceived(v *ERABSecurityResultListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSecurityResultListAPERValueFieldReplay(v *ERABSecurityResultListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListAPERValueFieldWithoutReplay(v *ERABSecurityResultListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultListERABSecurityResultItemIEBindingFieldCodec(v *ERABSecurityResultListERABSecurityResultItemIEBinding) *ERABSecurityResultItemValueCodec {
	return &v.codec
}
func BridgeERABSecurityResultListERABSecurityResultItemIEBindingFieldGet(v *ERABSecurityResultListERABSecurityResultItemIEBinding) *func(*ERABSecurityResultListIEValue) (*ERABSecurityResultItem, bool) {
	return &v.get
}
func BridgeERABSecurityResultListERABSecurityResultItemIEBindingFieldInfo(v *ERABSecurityResultListERABSecurityResultItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSecurityResultListERABSecurityResultItemIEBindingFieldInject(v *ERABSecurityResultListERABSecurityResultItemIEBinding) *func(ERABSecurityResultItem) ERABSecurityResultListIEValue {
	return &v.inject
}
func BridgeERABSecurityResultListIEContainerAPERValueFieldContext(v *ERABSecurityResultListIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEContainerAPERValueFieldReceived(v *ERABSecurityResultListIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSecurityResultListIEContainerAPERValueFieldReplay(v *ERABSecurityResultListIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListIEContainerAPERValueFieldWithoutReplay(v *ERABSecurityResultListIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultListIEContainerValueCodecFieldCapture(v *ERABSecurityResultListIEContainerValueCodec) *func(ERABSecurityResultListIEContainer, aper.DecodeState) (ERABSecurityResultListIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultListIEContainerValueCodecFieldCompare(v *ERABSecurityResultListIEContainerValueCodec) *func(ERABSecurityResultListIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultListIEContainerValueCodecFieldContext(v *ERABSecurityResultListIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEContainerValueCodecFieldDecode(v *ERABSecurityResultListIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultListIEContainer, error) {
	return &v.decode
}
func BridgeERABSecurityResultListIEContainerValueCodecFieldEncode(v *ERABSecurityResultListIEContainerValueCodec) *func(ERABSecurityResultListIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultListIEContainerValueCodecFieldPath(v *ERABSecurityResultListIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultListIEContainerValueCodecMethodEncodeBudgetValue(v ERABSecurityResultListIEContainerValueCodec, a0 ERABSecurityResultListIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSecurityResultListIEContainerValueCodecMethodEncodeChanged(v ERABSecurityResultListIEContainerValueCodec, a0 ERABSecurityResultListIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSecurityResultListIEFieldAPERValueFieldContext(v *ERABSecurityResultListIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEFieldAPERValueFieldReceived(v *ERABSecurityResultListIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSecurityResultListIEFieldAPERValueFieldReplay(v *ERABSecurityResultListIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListIEFieldAPERValueFieldWithoutReplay(v *ERABSecurityResultListIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultListIEFieldFieldReceived(v *ERABSecurityResultListIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABSecurityResultListIEFieldFieldReplay(v *ERABSecurityResultListIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListIEFieldFieldStream(v *ERABSecurityResultListIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSecurityResultListIEFieldFieldWithoutReplay(v *ERABSecurityResultListIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultListIEFieldMethodMarshalAPERTo(v *ERABSecurityResultListIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSecurityResultListIEFieldMethodUnmarshalAPERFrom(v *ERABSecurityResultListIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSecurityResultListIEFieldValueCodecFieldCapture(v *ERABSecurityResultListIEFieldValueCodec) *func(ERABSecurityResultListIEField, aper.DecodeState) (ERABSecurityResultListIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultListIEFieldValueCodecFieldCompare(v *ERABSecurityResultListIEFieldValueCodec) *func(ERABSecurityResultListIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultListIEFieldValueCodecFieldContext(v *ERABSecurityResultListIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEFieldValueCodecFieldDecode(v *ERABSecurityResultListIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultListIEField, error) {
	return &v.decode
}
func BridgeERABSecurityResultListIEFieldValueCodecFieldEncode(v *ERABSecurityResultListIEFieldValueCodec) *func(ERABSecurityResultListIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultListIEFieldValueCodecFieldPath(v *ERABSecurityResultListIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultListIEFieldValueCodecMethodEncodeBudgetValue(v ERABSecurityResultListIEFieldValueCodec, a0 ERABSecurityResultListIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSecurityResultListIEFieldValueCodecMethodEncodeChanged(v ERABSecurityResultListIEFieldValueCodec, a0 ERABSecurityResultListIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSecurityResultListIETableMethodInfoERABSecurityResultItem(v ERABSecurityResultListIETable) s00.FieldInfo {
	return v.infoERABSecurityResultItem()
}
func BridgeERABSecurityResultListIEValueERABIEContainerListAPERValueFieldContext(v *ERABSecurityResultListIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEValueERABIEContainerListAPERValueFieldReceived(v *ERABSecurityResultListIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSecurityResultListIEValueERABIEContainerListAPERValueFieldReplay(v *ERABSecurityResultListIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABSecurityResultListIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldCapture(v *ERABSecurityResultListIEValueERABIEContainerListValueCodec) *func(ERABSecurityResultListIEValueERABIEContainerList, aper.DecodeState) (ERABSecurityResultListIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldCompare(v *ERABSecurityResultListIEValueERABIEContainerListValueCodec) *func(ERABSecurityResultListIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldContext(v *ERABSecurityResultListIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldDecode(v *ERABSecurityResultListIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultListIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldEncode(v *ERABSecurityResultListIEValueERABIEContainerListValueCodec) *func(ERABSecurityResultListIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecFieldPath(v *ERABSecurityResultListIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSecurityResultListIEValueERABIEContainerListValueCodec, a0 ERABSecurityResultListIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSecurityResultListIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABSecurityResultListIEValueERABIEContainerListValueCodec, a0 ERABSecurityResultListIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSecurityResultListIEValueFieldId(v *ERABSecurityResultListIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABSecurityResultListIEValueFieldIsOpaque(v *ERABSecurityResultListIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABSecurityResultListIEValueFieldOpaque(v *ERABSecurityResultListIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABSecurityResultListIEValueFieldReceived(v *ERABSecurityResultListIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSecurityResultListIEValueFieldReplay(v *ERABSecurityResultListIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListIEValueFieldRowERABSecurityResultItem(v *ERABSecurityResultListIEValue) **ERABSecurityResultItem {
	return &v.rowERABSecurityResultItem
}
func BridgeERABSecurityResultListIEValueMethodCaptureSemantics(v ERABSecurityResultListIEValue, a0 aper.SemanticCapture) ERABSecurityResultListIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABSecurityResultListIEValueMethodCompareSemantics(v ERABSecurityResultListIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABSecurityResultListIEValueMethodDecode(v ERABSecurityResultListIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABSecurityResultListIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABSecurityResultListIEValueMethodEncode(v ERABSecurityResultListIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABSecurityResultListIEValueMethodEncodeFresh(v ERABSecurityResultListIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABSecurityResultListIEValueMethodMatchesID(v ERABSecurityResultListIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABSecurityResultListIEValueMethodReason(v ERABSecurityResultListIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABSecurityResultListIEValueMethodRule(v ERABSecurityResultListIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSecurityResultListIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSecurityResultListIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSecurityResultListIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultListIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSecurityResultListIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSecurityResultListIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABSecurityResultListIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSecurityResultListIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABSecurityResultListIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABSecurityResultListIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABSecurityResultListIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABSecurityResultListIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) *func(ERABSecurityResultListIEValueProtocolIEContainerList, aper.DecodeState) (ERABSecurityResultListIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) *func(ERABSecurityResultListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultListIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) *func(ERABSecurityResultListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABSecurityResultListIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSecurityResultListIEValueProtocolIEContainerListValueCodec, a0 ERABSecurityResultListIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSecurityResultListIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABSecurityResultListIEValueProtocolIEContainerListValueCodec, a0 ERABSecurityResultListIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSecurityResultListValueCodecFieldCapture(v *ERABSecurityResultListValueCodec) *func(ERABSecurityResultList, aper.DecodeState) (ERABSecurityResultList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultListValueCodecFieldCompare(v *ERABSecurityResultListValueCodec) *func(ERABSecurityResultList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultListValueCodecFieldContext(v *ERABSecurityResultListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultListValueCodecFieldDecode(v *ERABSecurityResultListValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultList, error) {
	return &v.decode
}
func BridgeERABSecurityResultListValueCodecFieldEncode(v *ERABSecurityResultListValueCodec) *func(ERABSecurityResultList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultListValueCodecFieldPath(v *ERABSecurityResultListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultListValueCodecMethodEncodeBudgetValue(v ERABSecurityResultListValueCodec, a0 ERABSecurityResultList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSecurityResultListValueCodecMethodEncodeChanged(v ERABSecurityResultListValueCodec, a0 ERABSecurityResultList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupListHOReqValueCodecFieldCapture(v *ERABToBeSetupListHOReqValueCodec) *func(s29.ERABToBeSetupListHOReq, aper.DecodeState) (s29.ERABToBeSetupListHOReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupListHOReqValueCodecFieldCompare(v *ERABToBeSetupListHOReqValueCodec) *func(s29.ERABToBeSetupListHOReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupListHOReqValueCodecFieldContext(v *ERABToBeSetupListHOReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupListHOReqValueCodecFieldDecode(v *ERABToBeSetupListHOReqValueCodec) *func([]byte, aper.DecodeState) (s29.ERABToBeSetupListHOReq, error) {
	return &v.decode
}
func BridgeERABToBeSetupListHOReqValueCodecFieldEncode(v *ERABToBeSetupListHOReqValueCodec) *func(s29.ERABToBeSetupListHOReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupListHOReqValueCodecFieldPath(v *ERABToBeSetupListHOReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupListHOReqValueCodecMethodEncodeBudgetValue(v ERABToBeSetupListHOReqValueCodec, a0 s29.ERABToBeSetupListHOReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupListHOReqValueCodecMethodEncodeChanged(v ERABToBeSetupListHOReqValueCodec, a0 s29.ERABToBeSetupListHOReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemAPERValueFieldContext(v *ERABToBeSwitchedDLItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemAPERValueFieldReceived(v *ERABToBeSwitchedDLItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemAPERValueFieldReplay(v *ERABToBeSwitchedDLItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBindingFieldCodec(v *ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding) *ERABToBeSwitchedDLItemValueCodec {
	return &v.codec
}
func BridgeERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBindingFieldGet(v *ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding) *func(*ERABToBeSwitchedDLItemIEValue) (*ERABToBeSwitchedDLItem, bool) {
	return &v.get
}
func BridgeERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBindingFieldInfo(v *ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBindingFieldInject(v *ERABToBeSwitchedDLItemERABToBeSwitchedDLItemIEBinding) *func(ERABToBeSwitchedDLItem) ERABToBeSwitchedDLItemIEValue {
	return &v.inject
}
func BridgeERABToBeSwitchedDLItemFieldExtCount(v *ERABToBeSwitchedDLItem) *int64   { return &v.extCount }
func BridgeERABToBeSwitchedDLItemFieldExtData(v *ERABToBeSwitchedDLItem) *[][]byte { return &v.extData }
func BridgeERABToBeSwitchedDLItemFieldExtOrigin(v *ERABToBeSwitchedDLItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABToBeSwitchedDLItemFieldExtPresent(v *ERABToBeSwitchedDLItem) *[]bool {
	return &v.extPresent
}
func BridgeERABToBeSwitchedDLItemFieldExtWire(v *ERABToBeSwitchedDLItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABToBeSwitchedDLItemFieldIEExtensionsIndef(v *ERABToBeSwitchedDLItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABToBeSwitchedDLItemFieldPerExtPadding(v *ERABToBeSwitchedDLItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABToBeSwitchedDLItemFieldPerPadding(v *ERABToBeSwitchedDLItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABToBeSwitchedDLItemFieldReceived(v *ERABToBeSwitchedDLItem) *bool { return &v.received }
func BridgeERABToBeSwitchedDLItemFieldReceivedAbsolute(v *ERABToBeSwitchedDLItem) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSwitchedDLItemFieldReceivedBytes(v *ERABToBeSwitchedDLItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSwitchedDLItemFieldReceivedLocation(v *ERABToBeSwitchedDLItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSwitchedDLItemFieldReplay(v *ERABToBeSwitchedDLItem) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemFieldStream(v *ERABToBeSwitchedDLItem) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSwitchedDLItemFieldWithoutReplay(v *ERABToBeSwitchedDLItem) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemIEContainerAPERValueFieldContext(v *ERABToBeSwitchedDLItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEContainerAPERValueFieldReceived(v *ERABToBeSwitchedDLItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemIEContainerAPERValueFieldReplay(v *ERABToBeSwitchedDLItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemIEContainerAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemIEContainerValueCodecFieldCapture(v *ERABToBeSwitchedDLItemIEContainerValueCodec) *func(ERABToBeSwitchedDLItemIEContainer, aper.DecodeState) (ERABToBeSwitchedDLItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLItemIEContainerValueCodecFieldCompare(v *ERABToBeSwitchedDLItemIEContainerValueCodec) *func(ERABToBeSwitchedDLItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLItemIEContainerValueCodecFieldContext(v *ERABToBeSwitchedDLItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEContainerValueCodecFieldDecode(v *ERABToBeSwitchedDLItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEContainer, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLItemIEContainerValueCodecFieldEncode(v *ERABToBeSwitchedDLItemIEContainerValueCodec) *func(ERABToBeSwitchedDLItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLItemIEContainerValueCodecFieldPath(v *ERABToBeSwitchedDLItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLItemIEContainerValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLItemIEContainerValueCodec, a0 ERABToBeSwitchedDLItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemIEContainerValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLItemIEContainerValueCodec, a0 ERABToBeSwitchedDLItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemIEFieldAPERValueFieldContext(v *ERABToBeSwitchedDLItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEFieldAPERValueFieldReceived(v *ERABToBeSwitchedDLItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemIEFieldAPERValueFieldReplay(v *ERABToBeSwitchedDLItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemIEFieldAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemIEFieldFieldReceived(v *ERABToBeSwitchedDLItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemIEFieldFieldReplay(v *ERABToBeSwitchedDLItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemIEFieldFieldStream(v *ERABToBeSwitchedDLItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSwitchedDLItemIEFieldFieldWithoutReplay(v *ERABToBeSwitchedDLItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemIEFieldMethodMarshalAPERTo(v *ERABToBeSwitchedDLItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSwitchedDLItemIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSwitchedDLItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSwitchedDLItemIEFieldValueCodecFieldCapture(v *ERABToBeSwitchedDLItemIEFieldValueCodec) *func(ERABToBeSwitchedDLItemIEField, aper.DecodeState) (ERABToBeSwitchedDLItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLItemIEFieldValueCodecFieldCompare(v *ERABToBeSwitchedDLItemIEFieldValueCodec) *func(ERABToBeSwitchedDLItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLItemIEFieldValueCodecFieldContext(v *ERABToBeSwitchedDLItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEFieldValueCodecFieldDecode(v *ERABToBeSwitchedDLItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEField, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLItemIEFieldValueCodecFieldEncode(v *ERABToBeSwitchedDLItemIEFieldValueCodec) *func(ERABToBeSwitchedDLItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLItemIEFieldValueCodecFieldPath(v *ERABToBeSwitchedDLItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLItemIEFieldValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLItemIEFieldValueCodec, a0 ERABToBeSwitchedDLItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemIEFieldValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLItemIEFieldValueCodec, a0 ERABToBeSwitchedDLItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemIETableMethodInfoERABToBeSwitchedDLItem(v ERABToBeSwitchedDLItemIETable) s00.FieldInfo {
	return v.infoERABToBeSwitchedDLItem()
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValueFieldContext(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValueFieldReceived(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValueFieldReplay(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodecFieldCapture(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodecFieldCompare(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodecFieldContext(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodecFieldDecode(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodecFieldEncode(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodecFieldPath(v *ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec, a0 ERABToBeSwitchedDLItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLItemIEValueERABIEContainerListValueCodec, a0 ERABToBeSwitchedDLItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemIEValueFieldId(v *ERABToBeSwitchedDLItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSwitchedDLItemIEValueFieldIsOpaque(v *ERABToBeSwitchedDLItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSwitchedDLItemIEValueFieldOpaque(v *ERABToBeSwitchedDLItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSwitchedDLItemIEValueFieldReceived(v *ERABToBeSwitchedDLItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemIEValueFieldReplay(v *ERABToBeSwitchedDLItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemIEValueFieldRowERABToBeSwitchedDLItem(v *ERABToBeSwitchedDLItemIEValue) **ERABToBeSwitchedDLItem {
	return &v.rowERABToBeSwitchedDLItem
}
func BridgeERABToBeSwitchedDLItemIEValueMethodCaptureSemantics(v ERABToBeSwitchedDLItemIEValue, a0 aper.SemanticCapture) ERABToBeSwitchedDLItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSwitchedDLItemIEValueMethodCompareSemantics(v ERABToBeSwitchedDLItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSwitchedDLItemIEValueMethodDecode(v ERABToBeSwitchedDLItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeSwitchedDLItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeSwitchedDLItemIEValueMethodEncode(v ERABToBeSwitchedDLItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeSwitchedDLItemIEValueMethodEncodeFresh(v ERABToBeSwitchedDLItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeSwitchedDLItemIEValueMethodMatchesID(v ERABToBeSwitchedDLItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSwitchedDLItemIEValueMethodReason(v ERABToBeSwitchedDLItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeSwitchedDLItemIEValueMethodRule(v ERABToBeSwitchedDLItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec, a0 ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLItemIEValueProtocolIEContainerListValueCodec, a0 ERABToBeSwitchedDLItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemMethodMarshalAPERBudget(v *ERABToBeSwitchedDLItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSwitchedDLItemMethodMarshalAPERBudgetValue(v *ERABToBeSwitchedDLItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSwitchedDLItemMethodMarshalAPERChanged(v *ERABToBeSwitchedDLItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemMethodMarshalAPERChangedValue(v *ERABToBeSwitchedDLItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemMethodMarshalAPERLegacy(v *ERABToBeSwitchedDLItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSwitchedDLItemMethodMarshalAPERNewValue(v *ERABToBeSwitchedDLItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSwitchedDLItemMethodMarshalAPERPlanned(v *ERABToBeSwitchedDLItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemMethodMarshalAPERTo(v *ERABToBeSwitchedDLItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSwitchedDLItemMethodUnmarshalAPERFrom(v *ERABToBeSwitchedDLItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSwitchedDLItemMethodUnmarshalAPERLegacy(v *ERABToBeSwitchedDLItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSwitchedDLItemMethodUnmarshalAPERWithOptions(v *ERABToBeSwitchedDLItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeSwitchedDLItemValueCodecFieldCapture(v *ERABToBeSwitchedDLItemValueCodec) *func(ERABToBeSwitchedDLItem, aper.DecodeState) (ERABToBeSwitchedDLItem, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLItemValueCodecFieldCompare(v *ERABToBeSwitchedDLItemValueCodec) *func(ERABToBeSwitchedDLItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLItemValueCodecFieldContext(v *ERABToBeSwitchedDLItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemValueCodecFieldDecode(v *ERABToBeSwitchedDLItemValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItem, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLItemValueCodecFieldEncode(v *ERABToBeSwitchedDLItemValueCodec) *func(ERABToBeSwitchedDLItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLItemValueCodecFieldPath(v *ERABToBeSwitchedDLItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLItemValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLItemValueCodec, a0 ERABToBeSwitchedDLItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLItemValueCodec, a0 ERABToBeSwitchedDLItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLListAPERValueFieldContext(v *ERABToBeSwitchedDLListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLListAPERValueFieldReceived(v *ERABToBeSwitchedDLListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLListAPERValueFieldReplay(v *ERABToBeSwitchedDLListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLListAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLListValueCodecFieldCapture(v *ERABToBeSwitchedDLListValueCodec) *func(ERABToBeSwitchedDLList, aper.DecodeState) (ERABToBeSwitchedDLList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLListValueCodecFieldCompare(v *ERABToBeSwitchedDLListValueCodec) *func(ERABToBeSwitchedDLList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLListValueCodecFieldContext(v *ERABToBeSwitchedDLListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLListValueCodecFieldDecode(v *ERABToBeSwitchedDLListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLList, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLListValueCodecFieldEncode(v *ERABToBeSwitchedDLListValueCodec) *func(ERABToBeSwitchedDLList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLListValueCodecFieldPath(v *ERABToBeSwitchedDLListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLListValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLListValueCodec, a0 ERABToBeSwitchedDLList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLListValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLListValueCodec, a0 ERABToBeSwitchedDLList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecurityResultAPERValueFieldContext(v *SecurityResultAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityResultAPERValueFieldReceived(v *SecurityResultAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecurityResultAPERValueFieldReplay(v *SecurityResultAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecurityResultAPERValueFieldWithoutReplay(v *SecurityResultAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecurityResultFieldExtCount(v *SecurityResult) *int64                { return &v.extCount }
func BridgeSecurityResultFieldExtData(v *SecurityResult) *[][]byte              { return &v.extData }
func BridgeSecurityResultFieldExtOrigin(v *SecurityResult) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeSecurityResultFieldExtPresent(v *SecurityResult) *[]bool             { return &v.extPresent }
func BridgeSecurityResultFieldExtWire(v *SecurityResult) *[]aper.WireSpan       { return &v.extWire }
func BridgeSecurityResultFieldIEExtensionsIndef(v *SecurityResult) *bool        { return &v.iEExtensionsIndef }
func BridgeSecurityResultFieldPerExtPadding(v *SecurityResult) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSecurityResultFieldPerPadding(v *SecurityResult) *aper.FinalPadding { return &v.perPadding }
func BridgeSecurityResultFieldReceived(v *SecurityResult) *bool                { return &v.received }
func BridgeSecurityResultFieldReceivedAbsolute(v *SecurityResult) *bool        { return &v.receivedAbsolute }
func BridgeSecurityResultFieldReceivedBytes(v *SecurityResult) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSecurityResultFieldReceivedLocation(v *SecurityResult) *aper.Location {
	return &v.receivedLocation
}
func BridgeSecurityResultFieldReplay(v *SecurityResult) *aper.Snapshot { return &v.replay }
func BridgeSecurityResultFieldStream(v *SecurityResult) *aper.WireSpan { return &v.stream }
func BridgeSecurityResultFieldWithoutReplay(v *SecurityResult) *bool   { return &v.withoutReplay }
func BridgeSecurityResultMethodMarshalAPERBudget(v *SecurityResult, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSecurityResultMethodMarshalAPERBudgetValue(v *SecurityResult, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSecurityResultMethodMarshalAPERChanged(v *SecurityResult, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSecurityResultMethodMarshalAPERChangedValue(v *SecurityResult, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSecurityResultMethodMarshalAPERLegacy(v *SecurityResult) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSecurityResultMethodMarshalAPERNewValue(v *SecurityResult, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSecurityResultMethodMarshalAPERPlanned(v *SecurityResult, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSecurityResultMethodMarshalAPERTo(v *SecurityResult, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecurityResultMethodUnmarshalAPERFrom(v *SecurityResult, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecurityResultMethodUnmarshalAPERLegacy(v *SecurityResult, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSecurityResultMethodUnmarshalAPERWithOptions(v *SecurityResult, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSecurityResultValueCodecFieldCapture(v *SecurityResultValueCodec) *func(SecurityResult, aper.DecodeState) (SecurityResult, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityResultValueCodecFieldCompare(v *SecurityResultValueCodec) *func(SecurityResult, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityResultValueCodecFieldContext(v *SecurityResultValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityResultValueCodecFieldDecode(v *SecurityResultValueCodec) *func([]byte, aper.DecodeState) (SecurityResult, error) {
	return &v.decode
}
func BridgeSecurityResultValueCodecFieldEncode(v *SecurityResultValueCodec) *func(SecurityResult, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityResultValueCodecFieldPath(v *SecurityResultValueCodec) *aper.Path { return &v.path }
func BridgeSecurityResultValueCodecMethodEncodeBudgetValue(v SecurityResultValueCodec, a0 SecurityResult, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecurityResultValueCodecMethodEncodeChanged(v SecurityResultValueCodec, a0 SecurityResult, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgeSensorNameConfigFieldPerOpenTypePadding(v *SensorNameConfig) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSensorNameConfigFieldPerPadding(v *SensorNameConfig) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSensorNameConfigFieldReceived(v *SensorNameConfig) *bool { return &v.received }
func BridgeSensorNameConfigFieldReceivedAbsolute(v *SensorNameConfig) *bool {
	return &v.receivedAbsolute
}
func BridgeSensorNameConfigFieldReceivedBytes(v *SensorNameConfig) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSensorNameConfigFieldReceivedLocation(v *SensorNameConfig) *aper.Location {
	return &v.receivedLocation
}
func BridgeSensorNameConfigFieldReplay(v *SensorNameConfig) *aper.Snapshot { return &v.replay }
func BridgeSensorNameConfigFieldStream(v *SensorNameConfig) *aper.WireSpan { return &v.stream }
func BridgeSensorNameConfigFieldWithoutReplay(v *SensorNameConfig) *bool   { return &v.withoutReplay }
func BridgeSensorNameConfigMethodMarshalAPERBudget(v *SensorNameConfig, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSensorNameConfigMethodMarshalAPERBudgetValue(v *SensorNameConfig, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSensorNameConfigMethodMarshalAPERChanged(v *SensorNameConfig, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSensorNameConfigMethodMarshalAPERChangedValue(v *SensorNameConfig, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSensorNameConfigMethodMarshalAPERLegacy(v *SensorNameConfig) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSensorNameConfigMethodMarshalAPERNewValue(v *SensorNameConfig, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSensorNameConfigMethodMarshalAPERPlanned(v *SensorNameConfig, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSensorNameConfigMethodMarshalAPERTo(v *SensorNameConfig, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSensorNameConfigMethodUnmarshalAPERFrom(v *SensorNameConfig, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSensorNameConfigMethodUnmarshalAPERLegacy(v *SensorNameConfig, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSensorNameConfigMethodUnmarshalAPERWithOptions(v *SensorNameConfig, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSensorNameConfigValueCodecFieldCapture(v *SensorNameConfigValueCodec) *func(SensorNameConfig, aper.DecodeState) (SensorNameConfig, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorNameConfigValueCodecFieldCompare(v *SensorNameConfigValueCodec) *func(SensorNameConfig, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorNameConfigValueCodecFieldContext(v *SensorNameConfigValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorNameConfigValueCodecFieldDecode(v *SensorNameConfigValueCodec) *func([]byte, aper.DecodeState) (SensorNameConfig, error) {
	return &v.decode
}
func BridgeSensorNameConfigValueCodecFieldEncode(v *SensorNameConfigValueCodec) *func(SensorNameConfig, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorNameConfigValueCodecFieldPath(v *SensorNameConfigValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorNameConfigValueCodecMethodEncodeBudgetValue(v SensorNameConfigValueCodec, a0 SensorNameConfig, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSensorNameConfigValueCodecMethodEncodeChanged(v SensorNameConfigValueCodec, a0 SensorNameConfig, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
