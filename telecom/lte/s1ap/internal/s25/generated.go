// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s25 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s25

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// PrivateMessageIEsValuePrivateIEContainer is PrivateIE-Container {{PrivateMessageIEs}} of TS 36.413: a list of PrivateMessageIEsValuePrivateIEField values.
type PrivateMessageIEsValuePrivateIEContainer []PrivateMessageIEsValuePrivateIEField

// PrivateMessageIEsValuePrivateIEField is PrivateIE-Field {{PrivateMessageIEs}} of TS 36.413: a private information element field.
type PrivateMessageIEsValuePrivateIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s20.PrivateIEID
	Criticality   s00.Criticality
	Value         PrivateMessageIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PrivateMessageIEsValuePrivateIEField) WithoutReplay() PrivateMessageIEsValuePrivateIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PrivateMessageIEsValuePrivateIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PrivateMessageIEsValuePrivateIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("nil PrivateIEField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the private value to @id, too.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: private field id does not match its value selector", aper.ErrInvalidValue), "PrivateIEField.Id")
	}
	if err := s20.BridgePrivateIEIDMethodMarshalAPERTo(&v.Id, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return aper.EncodeOpenTypeAligned(bb, data)
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PrivateMessageIEsValuePrivateIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil PrivateIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateMessageIEsValuePrivateIEField{}
	if err := s20.BridgePrivateIEIDMethodUnmarshalAPERFrom(&v.Id, bb); err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero PrivateMessageIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("PrivateIEField.Value")
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
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIESingleContainer(v *s16.ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIESingleContainer(v *s16.ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIESingleContainer(v *s16.ERABSetupItemBearerSUResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIESingleContainer(v *s16.ERABSetupItemBearerSUResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIESingleContainer(v *s17.ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIESingleContainer(v *s17.ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionContainer(v *s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionContainer(v *s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(v *s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(v *s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIESingleContainer(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIESingleContainer(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIESingleContainer(v *s17.ERABToBeSwitchedULItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIESingleContainer(v *s17.ERABToBeSwitchedULItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(v *s17.ERABUsageReportItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABUsageReportItemIEValueCompareS1APProtocolIESingleContainer(v *s17.ERABUsageReportItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABUsageReportItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainer(v *s18.HandoverCancelIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCancelIEValueCompareS1APProtocolIEContainer(v *s18.HandoverCancelIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *s22.HandoverCancelAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainer(v *s22.HandoverCancelAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainer(v *s22.HandoverFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverFailureIEValueCompareS1APProtocolIEContainer(v *s22.HandoverFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainer(v *s22.HandoverPreparationFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainer(v *s22.HandoverPreparationFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainer(v *s22.InitialContextSetupFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainer(v *s22.InitialContextSetupFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainer(v *s18.LocationReportingFailureIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainer(v *s18.LocationReportingFailureIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *s22.MMEConfigurationUpdateAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(v *s22.MMEConfigurationUpdateAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(v *s23.MMEConfigurationUpdateFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(v *s23.MMEConfigurationUpdateFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainer(v *s22.MMEStatusTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainer(v *s22.MMEStatusTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(v *s19.NASNonDeliveryIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainer(v *s19.NASNonDeliveryIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABToBeModifiedItemBearerModReqIEs}} of TS 36.413: a single information element field.
type ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer = ERABToBeModifiedItemBearerModReqIEField

// ERABToBeModifiedListBearerModReqValueCodec is the concrete ValueCodec[ERABToBeModifiedListBearerModReq].
type ERABToBeModifiedListBearerModReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedListBearerModReq,

		error)
	encode func(ERABToBeModifiedListBearerModReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedListBearerModReq, aper.DecodeState,

	) (ERABToBeModifiedListBearerModReq, aper.Snapshot,

	)
	compare func(ERABToBeModifiedListBearerModReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedListBearerModReqValueCodec) New(value ERABToBeModifiedListBearerModReq,

) (ERABToBeModifiedListBearerModReqAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedListBearerModReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedListBearerModReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedListBearerModReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedListBearerModReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedListBearerModReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedListBearerModReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedListBearerModReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedListBearerModReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedListBearerModReqAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedListBearerModReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedListBearerModReqValueCodec) EncodeAPER(value ERABToBeModifiedListBearerModReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedListBearerModReqValueCodec) encodeBudgetValue(value ERABToBeModifiedListBearerModReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedListBearerModReqValueCodec) encodeChanged(value ERABToBeModifiedListBearerModReq,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding binds ERABToBeModifiedItemBearerModReq to the E-RABToBeModifiedItemBearerModReqIEs object set of TS 36.413.
type ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding struct {
	info   s00.FieldInfo
	codec  ERABToBeModifiedItemBearerModReqValueCodec
	inject func(ERABToBeModifiedItemBearerModReq,

	) ERABToBeModifiedItemBearerModReqIEValue

	get func(*ERABToBeModifiedItemBearerModReqIEValue,

	) (*ERABToBeModifiedItemBearerModReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding) Codec() ERABToBeModifiedItemBearerModReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding) New(value ERABToBeModifiedItemBearerModReq,

) (ERABToBeModifiedItemBearerModReqIEField, error) {
	if b.inject == nil {
		return ERABToBeModifiedItemBearerModReqIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModReqIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModReqIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeModifiedItemBearerModReqIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeModifiedItemBearerModReqIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding) Get(field *ERABToBeModifiedItemBearerModReqIEField) (*ERABToBeModifiedItemBearerModReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABToBeModifiedItemBearerModReqValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModReq].
type ERABToBeModifiedItemBearerModReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReq,

		error)
	encode func(ERABToBeModifiedItemBearerModReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModReq, aper.DecodeState,

	) (ERABToBeModifiedItemBearerModReq, aper.Snapshot,

	)
	compare func(ERABToBeModifiedItemBearerModReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModReqValueCodec) New(value ERABToBeModifiedItemBearerModReq,

) (ERABToBeModifiedItemBearerModReqAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModReqAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModReqValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModReqValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModReqValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModReq,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModReqIEField is ProtocolIE-Field {{E-RABToBeModifiedItemBearerModReqIEs}} of TS 36.413: an information element field.
type ERABToBeModifiedItemBearerModReqIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeModifiedItemBearerModReqIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModReqIEField) WithoutReplay() ERABToBeModifiedItemBearerModReqIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeModifiedItemBearerModReqIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeModifiedItemBearerModReqIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeModifiedItemBearerModReqIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifiedItemBearerModReqIEField{}
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
	var zero ERABToBeModifiedItemBearerModReqIEValue

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

// HandoverCancelAcknowledgeValueCodec is the concrete ValueCodec[HandoverCancelAcknowledge].
type HandoverCancelAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelAcknowledge,

		error)
	encode func(HandoverCancelAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelAcknowledge, aper.DecodeState,

	) (HandoverCancelAcknowledge, aper.Snapshot,

	)
	compare func(HandoverCancelAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelAcknowledgeValueCodec) New(value HandoverCancelAcknowledge,

) (HandoverCancelAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelAcknowledgeValueCodec) EncodeAPER(value HandoverCancelAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverCancelAcknowledgeValueCodec) encodeBudgetValue(value HandoverCancelAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelAcknowledgeValueCodec) encodeChanged(value HandoverCancelAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelValueCodec is the concrete ValueCodec[HandoverCancel].
type HandoverCancelValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancel,

		error)
	encode func(HandoverCancel,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancel, aper.DecodeState,

	) (HandoverCancel, aper.Snapshot,

	)
	compare func(HandoverCancel, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelValueCodec) New(value HandoverCancel,

) (HandoverCancelAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelValueCodec) EncodeAPER(value HandoverCancelAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverCancelValueCodec) encodeBudgetValue(value HandoverCancel,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelValueCodec) encodeChanged(value HandoverCancel,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverFailureValueCodec is the concrete ValueCodec[HandoverFailure].
type HandoverFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverFailure,

		error)
	encode func(HandoverFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverFailure, aper.DecodeState,

	) (HandoverFailure, aper.Snapshot,

	)
	compare func(HandoverFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverFailureValueCodec) New(value HandoverFailure,

) (HandoverFailureAPERValue, error) {
	if c.encode == nil {
		return HandoverFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverFailureValueCodec) EncodeAPER(value HandoverFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverFailureValueCodec) encodeBudgetValue(value HandoverFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverFailureValueCodec) encodeChanged(value HandoverFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverPreparationFailureValueCodec is the concrete ValueCodec[HandoverPreparationFailure].
type HandoverPreparationFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverPreparationFailure,

		error)
	encode func(HandoverPreparationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverPreparationFailure, aper.DecodeState,

	) (HandoverPreparationFailure, aper.Snapshot,

	)
	compare func(HandoverPreparationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverPreparationFailureValueCodec) New(value HandoverPreparationFailure,

) (HandoverPreparationFailureAPERValue, error) {
	if c.encode == nil {
		return HandoverPreparationFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverPreparationFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverPreparationFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverPreparationFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverPreparationFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverPreparationFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverPreparationFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverPreparationFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverPreparationFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverPreparationFailureValueCodec) EncodeAPER(value HandoverPreparationFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverPreparationFailureValueCodec) encodeBudgetValue(value HandoverPreparationFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverPreparationFailureValueCodec) encodeChanged(value HandoverPreparationFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupFailureValueCodec is the concrete ValueCodec[InitialContextSetupFailure].
type InitialContextSetupFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupFailure,

		error)
	encode func(InitialContextSetupFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupFailure, aper.DecodeState,

	) (InitialContextSetupFailure, aper.Snapshot,

	)
	compare func(InitialContextSetupFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupFailureValueCodec) New(value InitialContextSetupFailure,

) (InitialContextSetupFailureAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupFailureValueCodec) EncodeAPER(value InitialContextSetupFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InitialContextSetupFailureValueCodec) encodeBudgetValue(value InitialContextSetupFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupFailureValueCodec) encodeChanged(value InitialContextSetupFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingFailureIndicationValueCodec is the concrete ValueCodec[LocationReportingFailureIndication].
type LocationReportingFailureIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingFailureIndication,

		error)
	encode func(LocationReportingFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingFailureIndication, aper.DecodeState,

	) (LocationReportingFailureIndication, aper.Snapshot,

	)
	compare func(LocationReportingFailureIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingFailureIndicationValueCodec) New(value LocationReportingFailureIndication,

) (LocationReportingFailureIndicationAPERValue, error) {
	if c.encode == nil {
		return LocationReportingFailureIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingFailureIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingFailureIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingFailureIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingFailureIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingFailureIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingFailureIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingFailureIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingFailureIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingFailureIndicationValueCodec) EncodeAPER(value LocationReportingFailureIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingFailureIndicationValueCodec) encodeBudgetValue(value LocationReportingFailureIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingFailureIndicationValueCodec) encodeChanged(value LocationReportingFailureIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateAcknowledgeValueCodec is the concrete ValueCodec[MMEConfigurationUpdateAcknowledge].
type MMEConfigurationUpdateAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledge,

		error)
	encode func(MMEConfigurationUpdateAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateAcknowledge, aper.DecodeState,

	) (MMEConfigurationUpdateAcknowledge, aper.Snapshot,

	)
	compare func(MMEConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateAcknowledgeValueCodec) New(value MMEConfigurationUpdateAcknowledge,

) (MMEConfigurationUpdateAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateAcknowledgeValueCodec) EncodeAPER(value MMEConfigurationUpdateAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationUpdateAcknowledgeValueCodec) encodeBudgetValue(value MMEConfigurationUpdateAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateAcknowledgeValueCodec) encodeChanged(value MMEConfigurationUpdateAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateFailureValueCodec is the concrete ValueCodec[MMEConfigurationUpdateFailure].
type MMEConfigurationUpdateFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailure,

		error)
	encode func(MMEConfigurationUpdateFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateFailure, aper.DecodeState,

	) (MMEConfigurationUpdateFailure, aper.Snapshot,

	)
	compare func(MMEConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateFailureValueCodec) New(value MMEConfigurationUpdateFailure,

) (MMEConfigurationUpdateFailureAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateFailureValueCodec) EncodeAPER(value MMEConfigurationUpdateFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationUpdateFailureValueCodec) encodeBudgetValue(value MMEConfigurationUpdateFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateFailureValueCodec) encodeChanged(value MMEConfigurationUpdateFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferValueCodec is the concrete ValueCodec[MMEStatusTransfer].
type MMEStatusTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransfer,

		error)
	encode func(MMEStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransfer, aper.DecodeState,

	) (MMEStatusTransfer, aper.Snapshot,

	)
	compare func(MMEStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferValueCodec) New(value MMEStatusTransfer,

) (MMEStatusTransferAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferValueCodec) EncodeAPER(value MMEStatusTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEStatusTransferValueCodec) encodeBudgetValue(value MMEStatusTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferValueCodec) encodeChanged(value MMEStatusTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASNonDeliveryIndicationValueCodec is the concrete ValueCodec[NASNonDeliveryIndication].
type NASNonDeliveryIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASNonDeliveryIndication,

		error)
	encode func(NASNonDeliveryIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASNonDeliveryIndication, aper.DecodeState,

	) (NASNonDeliveryIndication, aper.Snapshot,

	)
	compare func(NASNonDeliveryIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASNonDeliveryIndicationValueCodec) New(value NASNonDeliveryIndication,

) (NASNonDeliveryIndicationAPERValue, error) {
	if c.encode == nil {
		return NASNonDeliveryIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASNonDeliveryIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASNonDeliveryIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASNonDeliveryIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASNonDeliveryIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASNonDeliveryIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASNonDeliveryIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASNonDeliveryIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASNonDeliveryIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASNonDeliveryIndicationValueCodec) EncodeAPER(value NASNonDeliveryIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NASNonDeliveryIndicationValueCodec) encodeBudgetValue(value NASNonDeliveryIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASNonDeliveryIndicationValueCodec) encodeChanged(value NASNonDeliveryIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModReqIEContainer is ProtocolIE-Container {{E-RABToBeModifiedItemBearerModReqIEs}} of TS 36.413: a list of ERABToBeModifiedItemBearerModReqIEField values.
type ERABToBeModifiedItemBearerModReqIEContainer []ERABToBeModifiedItemBearerModReqIEField

// ERABReleaseItemBearerRelCompIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABReleaseItemBearerRelCompIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompIEValueERABIEContainerListCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable) s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec {
	codec := ERABReleaseItemBearerRelCompIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec{}
	}
	return func() s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec {
		sealed := s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec{}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerList(value), err
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(&codec))(s16.ERABReleaseItemBearerRelCompIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABSetupItemBearerSUResIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResIEValueERABIEContainerListCodec(table s00.ERABSetupItemBearerSUResIEValueIETable) s16.ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec {
	codec := ERABSetupItemBearerSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec{}
	}
	return func() s16.ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec {
		sealed := s16.ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec{}
		*s16.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABSetupItemBearerSUResIEValueERABIEContainerList(value), err
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABSetupItemBearerSUResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemBearerSUResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemBearerSUResIEValueERABIEContainerList, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemBearerSUResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABSetupItemCtxtSUResIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResIEValueERABIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s17.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec{}
	}
	return func() s17.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec {
		sealed := s17.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec{}
		*s17.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABSetupItemCtxtSUResIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABSetupItemCtxtSUResIEValueERABIEContainerList(value), err
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABSetupItemCtxtSUResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABSetupItemCtxtSUResIEValueERABIEContainerList, options aper.DecodeState) (s17.ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABSetupItemCtxtSUResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable) s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModIndIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec{}
	}
	return func() s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec {
		sealed := s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec{}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, error) {
			value, err := (*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList(value), err
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s17.ERABToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABToBeModifiedItemBearerModReqIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModReqIEValueIETable) ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec{}
	}
	return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList(value), err
	}, encode: func(value ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeModifiedItemBearerModReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ERABToBeSwitchedULItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABToBeSwitchedULItemIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemIEValueERABIEContainerListCodec(table s00.ERABToBeSwitchedULItemIEValueIETable) s17.ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec {
	codec := ERABToBeSwitchedULItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s17.ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec {
		sealed := s17.ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec{}
		*s17.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEValueERABIEContainerList, error) {
			value, err := (*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABToBeSwitchedULItemIEValueERABIEContainerList(value), err
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeSwitchedULItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(&codec))(s17.ERABToBeSwitchedULItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeSwitchedULItemIEValueERABIEContainerList, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeSwitchedULItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABUsageReportItemIEs}} codec of TS 36.413.
func ERABUsageReportItemIEValueERABIEContainerListCodec(table s00.ERABUsageReportItemIEValueIETable) s17.ERABUsageReportItemIEValueERABIEContainerListValueCodec {
	codec := ERABUsageReportItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABUsageReportItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s17.ERABUsageReportItemIEValueERABIEContainerListValueCodec {
		sealed := s17.ERABUsageReportItemIEValueERABIEContainerListValueCodec{}
		*s17.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABUsageReportItemIEValueERABIEContainerList, error) {
			value, err := (*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABUsageReportItemIEValueERABIEContainerList(value), err
		}
		*s17.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABUsageReportItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(&codec))(s17.ERABUsageReportItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABUsageReportItemIEValueERABIEContainerList, options aper.DecodeState) (s17.ERABUsageReportItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABUsageReportItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverCancelAcknowledgeIEs}} codec of TS 36.413.
func HandoverCancelAcknowledgeIEValueERABIEContainerListCodec(table s00.HandoverCancelAcknowledgeIEValueIETable) s22.HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := HandoverCancelAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	return func() s22.HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec {
		sealed := s22.HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec{}
		*s22.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEValueERABIEContainerList, error) {
			value, err := (*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverCancelAcknowledgeIEValueERABIEContainerList(value), err
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverCancelAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.HandoverCancelAcknowledgeIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverCancelAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverCancelAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverCancelIEs}} codec of TS 36.413.
func HandoverCancelIEValueERABIEContainerListCodec(table s00.HandoverCancelIEValueIETable) s18.HandoverCancelIEValueERABIEContainerListValueCodec {
	codec := HandoverCancelIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.HandoverCancelIEValueERABIEContainerListValueCodec{}
	}
	return func() s18.HandoverCancelIEValueERABIEContainerListValueCodec {
		sealed := s18.HandoverCancelIEValueERABIEContainerListValueCodec{}
		*s18.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.HandoverCancelIEValueERABIEContainerList, error) {
			value, err := (*s18.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s18.HandoverCancelIEValueERABIEContainerList(value), err
		}
		*s18.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.HandoverCancelIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeHandoverCancelIEContainerValueCodecFieldEncode(&codec))(s18.HandoverCancelIEContainer(value), fresh, budget)
		}
		*s18.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.HandoverCancelIEValueERABIEContainerList, options aper.DecodeState) (s18.HandoverCancelIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.HandoverCancelIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverFailureIEs}} codec of TS 36.413.
func HandoverFailureIEValueERABIEContainerListCodec(table s00.HandoverFailureIEValueIETable) s22.HandoverFailureIEValueERABIEContainerListValueCodec {
	codec := HandoverFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverFailureIEValueERABIEContainerListValueCodec{}
	}
	return func() s22.HandoverFailureIEValueERABIEContainerListValueCodec {
		sealed := s22.HandoverFailureIEValueERABIEContainerListValueCodec{}
		*s22.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverFailureIEValueERABIEContainerList, error) {
			value, err := (*s22.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverFailureIEValueERABIEContainerList(value), err
		}
		*s22.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverFailureIEContainerValueCodecFieldEncode(&codec))(s22.HandoverFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverFailureIEValueERABIEContainerList, options aper.DecodeState) (s22.HandoverFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverPreparationFailureIEs}} codec of TS 36.413.
func HandoverPreparationFailureIEValueERABIEContainerListCodec(table s00.HandoverPreparationFailureIEValueIETable) s22.HandoverPreparationFailureIEValueERABIEContainerListValueCodec {
	codec := HandoverPreparationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverPreparationFailureIEValueERABIEContainerListValueCodec{}
	}
	return func() s22.HandoverPreparationFailureIEValueERABIEContainerListValueCodec {
		sealed := s22.HandoverPreparationFailureIEValueERABIEContainerListValueCodec{}
		*s22.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverPreparationFailureIEValueERABIEContainerList, error) {
			value, err := (*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverPreparationFailureIEValueERABIEContainerList(value), err
		}
		*s22.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverPreparationFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(&codec))(s22.HandoverPreparationFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverPreparationFailureIEValueERABIEContainerList, options aper.DecodeState) (s22.HandoverPreparationFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverPreparationFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{InitialContextSetupFailureIEs}} codec of TS 36.413.
func InitialContextSetupFailureIEValueERABIEContainerListCodec(table s00.InitialContextSetupFailureIEValueIETable) s22.InitialContextSetupFailureIEValueERABIEContainerListValueCodec {
	codec := InitialContextSetupFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.InitialContextSetupFailureIEValueERABIEContainerListValueCodec{}
	}
	return func() s22.InitialContextSetupFailureIEValueERABIEContainerListValueCodec {
		sealed := s22.InitialContextSetupFailureIEValueERABIEContainerListValueCodec{}
		*s22.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.InitialContextSetupFailureIEValueERABIEContainerList, error) {
			value, err := (*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.InitialContextSetupFailureIEValueERABIEContainerList(value), err
		}
		*s22.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.InitialContextSetupFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(&codec))(s22.InitialContextSetupFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.InitialContextSetupFailureIEValueERABIEContainerList, options aper.DecodeState) (s22.InitialContextSetupFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.InitialContextSetupFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{LocationReportingFailureIndicationIEs}} codec of TS 36.413.
func LocationReportingFailureIndicationIEValueERABIEContainerListCodec(table s00.LocationReportingFailureIndicationIEValueIETable) s19.LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec {
	codec := LocationReportingFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec{}
	}
	return func() s19.LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec {
		sealed := s19.LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec{}
		*s19.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.LocationReportingFailureIndicationIEValueERABIEContainerList, error) {
			value, err := (*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s19.LocationReportingFailureIndicationIEValueERABIEContainerList(value), err
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.LocationReportingFailureIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s18.LocationReportingFailureIndicationIEContainer(value), fresh, budget)
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.LocationReportingFailureIndicationIEValueERABIEContainerList, options aper.DecodeState) (s19.LocationReportingFailureIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.LocationReportingFailureIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MDTMode-ExtensionIE}} codec of TS 36.413.
func MDTModeExtensionIEIEValueERABIEContainerListCodec(table s00.MDTModeExtensionIEIEValueIETable) s24.MDTModeExtensionIEIEValueERABIEContainerListValueCodec {
	codec := MDTModeExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.MDTModeExtensionIEIEValueERABIEContainerListValueCodec{}
	}
	return func() s24.MDTModeExtensionIEIEValueERABIEContainerListValueCodec {
		sealed := s24.MDTModeExtensionIEIEValueERABIEContainerListValueCodec{}
		*s24.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.MDTModeExtensionIEIEValueERABIEContainerList, error) {
			value, err := (*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.MDTModeExtensionIEIEValueERABIEContainerList(value), err
		}
		*s24.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.MDTModeExtensionIEIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(&codec))(s24.MDTModeExtensionIEIEContainer(value), fresh, budget)
		}
		*s24.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.MDTModeExtensionIEIEValueERABIEContainerList, options aper.DecodeState) (s24.MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.MDTModeExtensionIEIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable) s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := MMEConfigurationUpdateAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	return func() s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, error) {
			value, err := (*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList(value), err
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.MMEConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueERABIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable) s23.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
	}
	return func() s23.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, error) {
			value, err := (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList(value), err
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s23.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEStatusTransferIEs}} codec of TS 36.413.
func MMEStatusTransferIEValueERABIEContainerListCodec(table s00.MMEStatusTransferIEValueIETable) s22.MMEStatusTransferIEValueERABIEContainerListValueCodec {
	codec := MMEStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.MMEStatusTransferIEValueERABIEContainerListValueCodec{}
	}
	return func() s22.MMEStatusTransferIEValueERABIEContainerListValueCodec {
		sealed := s22.MMEStatusTransferIEValueERABIEContainerListValueCodec{}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEStatusTransferIEValueERABIEContainerList, error) {
			value, err := (*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.MMEStatusTransferIEValueERABIEContainerList(value), err
		}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.MMEStatusTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&codec))(s22.MMEStatusTransferIEContainer(value), fresh, budget)
		}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.MMEStatusTransferIEValueERABIEContainerList, options aper.DecodeState) (s22.MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.MMEStatusTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{NASNonDeliveryIndication-IEs}} codec of TS 36.413.
func NASNonDeliveryIndicationIEValueERABIEContainerListCodec(table s00.NASNonDeliveryIndicationIEValueIETable) s19.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec {
	codec := NASNonDeliveryIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec{}
	}
	return func() s19.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec {
		sealed := s19.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec{}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueERABIEContainerList, error) {
			value, err := (*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s19.NASNonDeliveryIndicationIEValueERABIEContainerList(value), err
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.NASNonDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s19.NASNonDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueERABIEContainerList, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifyItemBearerModReqExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABToBeModifyItemBearerModReqExtIEs}} codec of TS 36.413.
func ERABToBeModifyItemBearerModReqExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable) s21.ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeModifyItemBearerModReqExtIEsValueExtensionTableFieldBound(&table) {
		return s21.ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec{}
	}
	return func() s21.ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec {
		sealed := s21.ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec{}
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ERABToBeModifyItemBearerModReqExtIEsExtField, error) {
			var field s21.ERABToBeModifyItemBearerModReqExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s21.ERABToBeModifyItemBearerModReqExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s21.ERABToBeModifyItemBearerModReqExtIEsExtField, options aper.DecodeState) (s21.ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s21.ERABToBeModifyItemBearerModReqExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifyItemBearerModReqExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABToBeModifyItemBearerModReqExtIEs}} codec of TS 36.413.
func ERABToBeModifyItemBearerModReqExtIEsValueExtensionTableCodec(table s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable, bounds aper.ListBounds) s21.ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeModifyItemBearerModReqExtIEsValueExtensionTableFieldBound(&table) {
		return s21.ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s21.ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec {
		sealed := s21.ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec{}
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.ERABToBeModifyItemBearerModReqExtIEsExtField
					if err := s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer, options aper.DecodeState) (s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABReleaseItemBearerRelCompIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompIEValueIEFieldTableCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable) s16.ERABReleaseItemBearerRelCompIEFieldValueCodec {
	if !*s00.BridgeERABReleaseItemBearerRelCompIEValueIETableFieldBound(&table) {
		return s16.ERABReleaseItemBearerRelCompIEFieldValueCodec{}
	}
	return func() s16.ERABReleaseItemBearerRelCompIEFieldValueCodec {
		sealed := s16.ERABReleaseItemBearerRelCompIEFieldValueCodec{}
		*s16.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEField, error) {
			var field s16.ERABReleaseItemBearerRelCompIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABReleaseItemBearerRelCompIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABReleaseItemBearerRelCompIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEField, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABSetupItemBearerSUResIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResIEValueIEFieldTableCodec(table s00.ERABSetupItemBearerSUResIEValueIETable) s16.ERABSetupItemBearerSUResIEFieldValueCodec {
	if !*s00.BridgeERABSetupItemBearerSUResIEValueIETableFieldBound(&table) {
		return s16.ERABSetupItemBearerSUResIEFieldValueCodec{}
	}
	return func() s16.ERABSetupItemBearerSUResIEFieldValueCodec {
		sealed := s16.ERABSetupItemBearerSUResIEFieldValueCodec{}
		*s16.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEField, error) {
			var field s16.ERABSetupItemBearerSUResIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s16.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABSetupItemBearerSUResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABSetupItemBearerSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemBearerSUResIEField, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s16.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemBearerSUResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABSetupItemCtxtSUResIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResIEValueIEFieldTableCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s17.ERABSetupItemCtxtSUResIEFieldValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResIEValueIETableFieldBound(&table) {
		return s17.ERABSetupItemCtxtSUResIEFieldValueCodec{}
	}
	return func() s17.ERABSetupItemCtxtSUResIEFieldValueCodec {
		sealed := s17.ERABSetupItemCtxtSUResIEFieldValueCodec{}
		*s17.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEField, error) {
			var field s16.ERABSetupItemCtxtSUResIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s17.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABSetupItemCtxtSUResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEField, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s17.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndIEValueIEFieldTableCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable) s17.ERABToBeModifiedItemBearerModIndIEFieldValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModIndIEValueIETableFieldBound(&table) {
		return s17.ERABToBeModifiedItemBearerModIndIEFieldValueCodec{}
	}
	return func() s17.ERABToBeModifiedItemBearerModIndIEFieldValueCodec {
		sealed := s17.ERABToBeModifiedItemBearerModIndIEFieldValueCodec{}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEField, error) {
			var field s17.ERABToBeModifiedItemBearerModIndIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s17.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldEncode(&sealed) = func(field s17.ERABToBeModifiedItemBearerModIndIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s17.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEField, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModReqIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABToBeModifiedItemBearerModReqIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModReqIEValueIEFieldTableCodec(table s00.ERABToBeModifiedItemBearerModReqIEValueIETable) ERABToBeModifiedItemBearerModReqIEFieldValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModReqIEValueIETableFieldBound(&table) {
		return ERABToBeModifiedItemBearerModReqIEFieldValueCodec{}
	}
	return ERABToBeModifiedItemBearerModReqIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEField, error) {
		var field ERABToBeModifiedItemBearerModReqIEField
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
	}, encode: func(field ERABToBeModifiedItemBearerModReqIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABToBeModifiedItemBearerModReqIEField, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABToBeModifiedItemBearerModReqIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEField(&v, &s)
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

// ERABToBeSwitchedULItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABToBeSwitchedULItemIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemIEValueIEFieldTableCodec(table s00.ERABToBeSwitchedULItemIEValueIETable) s17.ERABToBeSwitchedULItemIEFieldValueCodec {
	if !*s00.BridgeERABToBeSwitchedULItemIEValueIETableFieldBound(&table) {
		return s17.ERABToBeSwitchedULItemIEFieldValueCodec{}
	}
	return func() s17.ERABToBeSwitchedULItemIEFieldValueCodec {
		sealed := s17.ERABToBeSwitchedULItemIEFieldValueCodec{}
		*s17.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEField, error) {
			var field s17.ERABToBeSwitchedULItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s17.BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s17.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldEncode(&sealed) = func(field s17.ERABToBeSwitchedULItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s17.BridgeERABToBeSwitchedULItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeSwitchedULItemIEField, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s17.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeSwitchedULItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABUsageReportItemIEs}} codec of TS 36.413.
func ERABUsageReportItemIEValueIEFieldTableCodec(table s00.ERABUsageReportItemIEValueIETable) s17.ERABUsageReportItemIEFieldValueCodec {
	if !*s00.BridgeERABUsageReportItemIEValueIETableFieldBound(&table) {
		return s17.ERABUsageReportItemIEFieldValueCodec{}
	}
	return func() s17.ERABUsageReportItemIEFieldValueCodec {
		sealed := s17.ERABUsageReportItemIEFieldValueCodec{}
		*s17.BridgeERABUsageReportItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABUsageReportItemIEField, error) {
			var field s17.ERABUsageReportItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s17.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s17.BridgeERABUsageReportItemIEFieldValueCodecFieldEncode(&sealed) = func(field s17.ERABUsageReportItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s17.BridgeERABUsageReportItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeERABUsageReportItemIEFieldValueCodecFieldCapture(&sealed) = func(v s17.ERABUsageReportItemIEField, options aper.DecodeState) (s17.ERABUsageReportItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s17.BridgeERABUsageReportItemIEFieldValueCodecFieldCompare(&sealed) = func(v s17.ERABUsageReportItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABUsageReportItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverCancelAcknowledgeIEs}} codec of TS 36.413.
func HandoverCancelAcknowledgeIEValueIEFieldTableCodec(table s00.HandoverCancelAcknowledgeIEValueIETable) s22.HandoverCancelAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeHandoverCancelAcknowledgeIEValueIETableFieldBound(&table) {
		return s22.HandoverCancelAcknowledgeIEFieldValueCodec{}
	}
	return func() s22.HandoverCancelAcknowledgeIEFieldValueCodec {
		sealed := s22.HandoverCancelAcknowledgeIEFieldValueCodec{}
		*s22.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEField, error) {
			var field s22.HandoverCancelAcknowledgeIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s22.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldEncode(&sealed) = func(field s22.HandoverCancelAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s22.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldCapture(&sealed) = func(v s22.HandoverCancelAcknowledgeIEField, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s22.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldCompare(&sealed) = func(v s22.HandoverCancelAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverCancelIEs}} codec of TS 36.413.
func HandoverCancelIEValueIEFieldTableCodec(table s00.HandoverCancelIEValueIETable) s18.HandoverCancelIEFieldValueCodec {
	if !*s00.BridgeHandoverCancelIEValueIETableFieldBound(&table) {
		return s18.HandoverCancelIEFieldValueCodec{}
	}
	return func() s18.HandoverCancelIEFieldValueCodec {
		sealed := s18.HandoverCancelIEFieldValueCodec{}
		*s18.BridgeHandoverCancelIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.HandoverCancelIEField, error) {
			var field s18.HandoverCancelIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s18.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s18.BridgeHandoverCancelIEFieldValueCodecFieldEncode(&sealed) = func(field s18.HandoverCancelIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s18.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s18.BridgeHandoverCancelIEFieldValueCodecFieldCapture(&sealed) = func(v s18.HandoverCancelIEField, options aper.DecodeState) (s18.HandoverCancelIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s18.BridgeHandoverCancelIEFieldValueCodecFieldCompare(&sealed) = func(v s18.HandoverCancelIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeHandoverCancelIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverFailureIEs}} codec of TS 36.413.
func HandoverFailureIEValueIEFieldTableCodec(table s00.HandoverFailureIEValueIETable) s22.HandoverFailureIEFieldValueCodec {
	if !*s00.BridgeHandoverFailureIEValueIETableFieldBound(&table) {
		return s22.HandoverFailureIEFieldValueCodec{}
	}
	return func() s22.HandoverFailureIEFieldValueCodec {
		sealed := s22.HandoverFailureIEFieldValueCodec{}
		*s22.BridgeHandoverFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverFailureIEField, error) {
			var field s22.HandoverFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s22.BridgeHandoverFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s22.HandoverFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s22.BridgeHandoverFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s22.HandoverFailureIEField, options aper.DecodeState) (s22.HandoverFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s22.BridgeHandoverFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s22.HandoverFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverPreparationFailureIEs}} codec of TS 36.413.
func HandoverPreparationFailureIEValueIEFieldTableCodec(table s00.HandoverPreparationFailureIEValueIETable) s22.HandoverPreparationFailureIEFieldValueCodec {
	if !*s00.BridgeHandoverPreparationFailureIEValueIETableFieldBound(&table) {
		return s22.HandoverPreparationFailureIEFieldValueCodec{}
	}
	return func() s22.HandoverPreparationFailureIEFieldValueCodec {
		sealed := s22.HandoverPreparationFailureIEFieldValueCodec{}
		*s22.BridgeHandoverPreparationFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverPreparationFailureIEField, error) {
			var field s22.HandoverPreparationFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s22.BridgeHandoverPreparationFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s22.HandoverPreparationFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s22.BridgeHandoverPreparationFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s22.HandoverPreparationFailureIEField, options aper.DecodeState) (s22.HandoverPreparationFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s22.BridgeHandoverPreparationFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s22.HandoverPreparationFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverPreparationFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{InitialContextSetupFailureIEs}} codec of TS 36.413.
func InitialContextSetupFailureIEValueIEFieldTableCodec(table s00.InitialContextSetupFailureIEValueIETable) s22.InitialContextSetupFailureIEFieldValueCodec {
	if !*s00.BridgeInitialContextSetupFailureIEValueIETableFieldBound(&table) {
		return s22.InitialContextSetupFailureIEFieldValueCodec{}
	}
	return func() s22.InitialContextSetupFailureIEFieldValueCodec {
		sealed := s22.InitialContextSetupFailureIEFieldValueCodec{}
		*s22.BridgeInitialContextSetupFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.InitialContextSetupFailureIEField, error) {
			var field s22.InitialContextSetupFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s22.BridgeInitialContextSetupFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s22.InitialContextSetupFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s22.BridgeInitialContextSetupFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s22.InitialContextSetupFailureIEField, options aper.DecodeState) (s22.InitialContextSetupFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s22.BridgeInitialContextSetupFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s22.InitialContextSetupFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeInitialContextSetupFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{LocationReportingFailureIndicationIEs}} codec of TS 36.413.
func LocationReportingFailureIndicationIEValueIEFieldTableCodec(table s00.LocationReportingFailureIndicationIEValueIETable) s19.LocationReportingFailureIndicationIEFieldValueCodec {
	if !*s00.BridgeLocationReportingFailureIndicationIEValueIETableFieldBound(&table) {
		return s19.LocationReportingFailureIndicationIEFieldValueCodec{}
	}
	return func() s19.LocationReportingFailureIndicationIEFieldValueCodec {
		sealed := s19.LocationReportingFailureIndicationIEFieldValueCodec{}
		*s19.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LocationReportingFailureIndicationIEField, error) {
			var field s18.LocationReportingFailureIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s18.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s19.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s18.LocationReportingFailureIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s18.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s18.LocationReportingFailureIndicationIEField, options aper.DecodeState) (s18.LocationReportingFailureIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s19.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s18.LocationReportingFailureIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MDTMode-ExtensionIE}} codec of TS 36.413.
func MDTModeExtensionIEIEValueIEFieldTableCodec(table s00.MDTModeExtensionIEIEValueIETable) s24.MDTModeExtensionIEIEFieldValueCodec {
	if !*s00.BridgeMDTModeExtensionIEIEValueIETableFieldBound(&table) {
		return s24.MDTModeExtensionIEIEFieldValueCodec{}
	}
	return func() s24.MDTModeExtensionIEIEFieldValueCodec {
		sealed := s24.MDTModeExtensionIEIEFieldValueCodec{}
		*s24.BridgeMDTModeExtensionIEIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.MDTModeExtensionIEIEField, error) {
			var field s24.MDTModeExtensionIEIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s24.BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s24.BridgeMDTModeExtensionIEIEFieldValueCodecFieldEncode(&sealed) = func(field s24.MDTModeExtensionIEIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s24.BridgeMDTModeExtensionIEIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s24.BridgeMDTModeExtensionIEIEFieldValueCodecFieldCapture(&sealed) = func(v s24.MDTModeExtensionIEIEField, options aper.DecodeState) (s24.MDTModeExtensionIEIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s24.BridgeMDTModeExtensionIEIEFieldValueCodecFieldCompare(&sealed) = func(v s24.MDTModeExtensionIEIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeMDTModeExtensionIEIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func MMEConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable) s23.MMEConfigurationUpdateAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&table) {
		return s23.MMEConfigurationUpdateAcknowledgeIEFieldValueCodec{}
	}
	return func() s23.MMEConfigurationUpdateAcknowledgeIEFieldValueCodec {
		sealed := s23.MMEConfigurationUpdateAcknowledgeIEFieldValueCodec{}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEConfigurationUpdateAcknowledgeIEField, error) {
			var field s22.MMEConfigurationUpdateAcknowledgeIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldEncode(&sealed) = func(field s22.MMEConfigurationUpdateAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCapture(&sealed) = func(v s22.MMEConfigurationUpdateAcknowledgeIEField, options aper.DecodeState) (s22.MMEConfigurationUpdateAcknowledgeIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCompare(&sealed) = func(v s22.MMEConfigurationUpdateAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueIEFieldTableCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable) s23.MMEConfigurationUpdateFailureIEFieldValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateFailureIEValueIETableFieldBound(&table) {
		return s23.MMEConfigurationUpdateFailureIEFieldValueCodec{}
	}
	return func() s23.MMEConfigurationUpdateFailureIEFieldValueCodec {
		sealed := s23.MMEConfigurationUpdateFailureIEFieldValueCodec{}
		*s23.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEField, error) {
			var field s23.MMEConfigurationUpdateFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s23.MMEConfigurationUpdateFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEField, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEStatusTransferIEs}} codec of TS 36.413.
func MMEStatusTransferIEValueIEFieldTableCodec(table s00.MMEStatusTransferIEValueIETable) s22.MMEStatusTransferIEFieldValueCodec {
	if !*s00.BridgeMMEStatusTransferIEValueIETableFieldBound(&table) {
		return s22.MMEStatusTransferIEFieldValueCodec{}
	}
	return func() s22.MMEStatusTransferIEFieldValueCodec {
		sealed := s22.MMEStatusTransferIEFieldValueCodec{}
		*s22.BridgeMMEStatusTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEStatusTransferIEField, error) {
			var field s22.MMEStatusTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s22.BridgeMMEStatusTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s22.MMEStatusTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s22.BridgeMMEStatusTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s22.MMEStatusTransferIEField, options aper.DecodeState) (s22.MMEStatusTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s22.BridgeMMEStatusTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s22.MMEStatusTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeMMEStatusTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{NASNonDeliveryIndication-IEs}} codec of TS 36.413.
func NASNonDeliveryIndicationIEValueIEFieldTableCodec(table s00.NASNonDeliveryIndicationIEValueIETable) s19.NASNonDeliveryIndicationIEFieldValueCodec {
	if !*s00.BridgeNASNonDeliveryIndicationIEValueIETableFieldBound(&table) {
		return s19.NASNonDeliveryIndicationIEFieldValueCodec{}
	}
	return func() s19.NASNonDeliveryIndicationIEFieldValueCodec {
		sealed := s19.NASNonDeliveryIndicationIEFieldValueCodec{}
		*s19.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEField, error) {
			var field s19.NASNonDeliveryIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s19.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s19.NASNonDeliveryIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s19.NASNonDeliveryIndicationIEField, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s19.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s19.NASNonDeliveryIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABReleaseItemBearerRelCompIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompIEValueIETableCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable, bounds aper.ListBounds) s16.ERABReleaseItemBearerRelCompIEContainerValueCodec {
	if !*s00.BridgeERABReleaseItemBearerRelCompIEValueIETableFieldBound(&table) {
		return s16.ERABReleaseItemBearerRelCompIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.ERABReleaseItemBearerRelCompIEContainerValueCodec {
		sealed := s16.ERABReleaseItemBearerRelCompIEContainerValueCodec{}
		*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.ERABReleaseItemBearerRelCompIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.ERABReleaseItemBearerRelCompIEField
					if err := s16.BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(&sealed) = func(fields s16.ERABReleaseItemBearerRelCompIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeERABReleaseItemBearerRelCompIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldCapture(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEContainer, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldCompare(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABSetupItemBearerSUResIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResIEValueIETableCodec(table s00.ERABSetupItemBearerSUResIEValueIETable, bounds aper.ListBounds) s16.ERABSetupItemBearerSUResIEContainerValueCodec {
	if !*s00.BridgeERABSetupItemBearerSUResIEValueIETableFieldBound(&table) {
		return s16.ERABSetupItemBearerSUResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.ERABSetupItemBearerSUResIEContainerValueCodec {
		sealed := s16.ERABSetupItemBearerSUResIEContainerValueCodec{}
		*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.ERABSetupItemBearerSUResIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.ERABSetupItemBearerSUResIEField
					if err := s16.BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(&sealed) = func(fields s16.ERABSetupItemBearerSUResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeERABSetupItemBearerSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemBearerSUResIEContainer, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemBearerSUResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABSetupItemCtxtSUResIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResIEValueIETableCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable, bounds aper.ListBounds) s16.ERABSetupItemCtxtSUResIEContainerValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResIEValueIETableFieldBound(&table) {
		return s16.ERABSetupItemCtxtSUResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.ERABSetupItemCtxtSUResIEContainerValueCodec {
		sealed := s16.ERABSetupItemCtxtSUResIEContainerValueCodec{}
		*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.ERABSetupItemCtxtSUResIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.ERABSetupItemCtxtSUResIEField
					if err := s16.BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&sealed) = func(fields s16.ERABSetupItemCtxtSUResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEContainer, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndIEValueIETableCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s17.ERABToBeModifiedItemBearerModIndIEContainerValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModIndIEValueIETableFieldBound(&table) {
		return s17.ERABToBeModifiedItemBearerModIndIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s17.ERABToBeModifiedItemBearerModIndIEContainerValueCodec {
		sealed := s17.ERABToBeModifiedItemBearerModIndIEContainerValueCodec{}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.ERABToBeModifiedItemBearerModIndIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.ERABToBeModifiedItemBearerModIndIEField
					if err := s17.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&sealed) = func(fields s17.ERABToBeModifiedItemBearerModIndIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s17.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEContainer, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModReqIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABToBeModifiedItemBearerModReqIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModReqIEValueIETableCodec(table s00.ERABToBeModifiedItemBearerModReqIEValueIETable, bounds aper.ListBounds) ERABToBeModifiedItemBearerModReqIEContainerValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModReqIEValueIETableFieldBound(&table) {
		return ERABToBeModifiedItemBearerModReqIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABToBeModifiedItemBearerModReqIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeModifiedItemBearerModReqIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeModifiedItemBearerModReqIEField
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
		encode: func(fields ERABToBeModifiedItemBearerModReqIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABToBeModifiedItemBearerModReqIEContainer, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeModifiedItemBearerModReqIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ERABToBeSwitchedULItemIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABToBeSwitchedULItemIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemIEValueIETableCodec(table s00.ERABToBeSwitchedULItemIEValueIETable, bounds aper.ListBounds) s17.ERABToBeSwitchedULItemIEContainerValueCodec {
	if !*s00.BridgeERABToBeSwitchedULItemIEValueIETableFieldBound(&table) {
		return s17.ERABToBeSwitchedULItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s17.ERABToBeSwitchedULItemIEContainerValueCodec {
		sealed := s17.ERABToBeSwitchedULItemIEContainerValueCodec{}
		*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.ERABToBeSwitchedULItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.ERABToBeSwitchedULItemIEField
					if err := s17.BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s17.ERABToBeSwitchedULItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s17.BridgeERABToBeSwitchedULItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeSwitchedULItemIEContainer, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeSwitchedULItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABUsageReportItemIEs}} codec of TS 36.413.
func ERABUsageReportItemIEValueIETableCodec(table s00.ERABUsageReportItemIEValueIETable, bounds aper.ListBounds) s17.ERABUsageReportItemIEContainerValueCodec {
	if !*s00.BridgeERABUsageReportItemIEValueIETableFieldBound(&table) {
		return s17.ERABUsageReportItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s17.ERABUsageReportItemIEContainerValueCodec {
		sealed := s17.ERABUsageReportItemIEContainerValueCodec{}
		*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABUsageReportItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.ERABUsageReportItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.ERABUsageReportItemIEField
					if err := s17.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s17.ERABUsageReportItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s17.BridgeERABUsageReportItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldCapture(&sealed) = func(v s17.ERABUsageReportItemIEContainer, options aper.DecodeState) (s17.ERABUsageReportItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldCompare(&sealed) = func(v s17.ERABUsageReportItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverCancelAcknowledgeIEs}} codec of TS 36.413.
func HandoverCancelAcknowledgeIEValueIETableCodec(table s00.HandoverCancelAcknowledgeIEValueIETable, bounds aper.ListBounds) s22.HandoverCancelAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeHandoverCancelAcknowledgeIEValueIETableFieldBound(&table) {
		return s22.HandoverCancelAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.HandoverCancelAcknowledgeIEContainerValueCodec {
		sealed := s22.HandoverCancelAcknowledgeIEContainerValueCodec{}
		*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.HandoverCancelAcknowledgeIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.HandoverCancelAcknowledgeIEField
					if err := s22.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.HandoverCancelAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldCapture(&sealed) = func(v s22.HandoverCancelAcknowledgeIEContainer, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldCompare(&sealed) = func(v s22.HandoverCancelAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverCancelIEs}} codec of TS 36.413.
func HandoverCancelIEValueIETableCodec(table s00.HandoverCancelIEValueIETable, bounds aper.ListBounds) s18.HandoverCancelIEContainerValueCodec {
	if !*s00.BridgeHandoverCancelIEValueIETableFieldBound(&table) {
		return s18.HandoverCancelIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s18.HandoverCancelIEContainerValueCodec {
		sealed := s18.HandoverCancelIEContainerValueCodec{}
		*s18.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.HandoverCancelIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.HandoverCancelIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.HandoverCancelIEField
					if err := s18.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s18.BridgeHandoverCancelIEContainerValueCodecFieldEncode(&sealed) = func(fields s18.HandoverCancelIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s18.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s18.BridgeHandoverCancelIEContainerValueCodecFieldCapture(&sealed) = func(v s18.HandoverCancelIEContainer, options aper.DecodeState) (s18.HandoverCancelIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeHandoverCancelIEContainerValueCodecFieldCompare(&sealed) = func(v s18.HandoverCancelIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeHandoverCancelIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverFailureIEs}} codec of TS 36.413.
func HandoverFailureIEValueIETableCodec(table s00.HandoverFailureIEValueIETable, bounds aper.ListBounds) s22.HandoverFailureIEContainerValueCodec {
	if !*s00.BridgeHandoverFailureIEValueIETableFieldBound(&table) {
		return s22.HandoverFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.HandoverFailureIEContainerValueCodec {
		sealed := s22.HandoverFailureIEContainerValueCodec{}
		*s22.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.HandoverFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.HandoverFailureIEField
					if err := s22.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s22.BridgeHandoverFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.HandoverFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeHandoverFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s22.HandoverFailureIEContainer, options aper.DecodeState) (s22.HandoverFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s22.HandoverFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverPreparationFailureIEs}} codec of TS 36.413.
func HandoverPreparationFailureIEValueIETableCodec(table s00.HandoverPreparationFailureIEValueIETable, bounds aper.ListBounds) s22.HandoverPreparationFailureIEContainerValueCodec {
	if !*s00.BridgeHandoverPreparationFailureIEValueIETableFieldBound(&table) {
		return s22.HandoverPreparationFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.HandoverPreparationFailureIEContainerValueCodec {
		sealed := s22.HandoverPreparationFailureIEContainerValueCodec{}
		*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverPreparationFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.HandoverPreparationFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.HandoverPreparationFailureIEField
					if err := s22.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.HandoverPreparationFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s22.HandoverPreparationFailureIEContainer, options aper.DecodeState) (s22.HandoverPreparationFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s22.HandoverPreparationFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupFailureIEValueIETableCodec constructs the ProtocolIE-Container {{InitialContextSetupFailureIEs}} codec of TS 36.413.
func InitialContextSetupFailureIEValueIETableCodec(table s00.InitialContextSetupFailureIEValueIETable, bounds aper.ListBounds) s22.InitialContextSetupFailureIEContainerValueCodec {
	if !*s00.BridgeInitialContextSetupFailureIEValueIETableFieldBound(&table) {
		return s22.InitialContextSetupFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.InitialContextSetupFailureIEContainerValueCodec {
		sealed := s22.InitialContextSetupFailureIEContainerValueCodec{}
		*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.InitialContextSetupFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.InitialContextSetupFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.InitialContextSetupFailureIEField
					if err := s22.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.InitialContextSetupFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s22.InitialContextSetupFailureIEContainer, options aper.DecodeState) (s22.InitialContextSetupFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s22.InitialContextSetupFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{LocationReportingFailureIndicationIEs}} codec of TS 36.413.
func LocationReportingFailureIndicationIEValueIETableCodec(table s00.LocationReportingFailureIndicationIEValueIETable, bounds aper.ListBounds) s18.LocationReportingFailureIndicationIEContainerValueCodec {
	if !*s00.BridgeLocationReportingFailureIndicationIEValueIETableFieldBound(&table) {
		return s18.LocationReportingFailureIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s18.LocationReportingFailureIndicationIEContainerValueCodec {
		sealed := s18.LocationReportingFailureIndicationIEContainerValueCodec{}
		*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LocationReportingFailureIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.LocationReportingFailureIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.LocationReportingFailureIndicationIEField
					if err := s18.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s18.LocationReportingFailureIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s18.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s18.LocationReportingFailureIndicationIEContainer, options aper.DecodeState) (s18.LocationReportingFailureIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s18.LocationReportingFailureIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueIETableCodec constructs the ProtocolIE-Container {{MDTMode-ExtensionIE}} codec of TS 36.413.
func MDTModeExtensionIEIEValueIETableCodec(table s00.MDTModeExtensionIEIEValueIETable, bounds aper.ListBounds) s24.MDTModeExtensionIEIEContainerValueCodec {
	if !*s00.BridgeMDTModeExtensionIEIEValueIETableFieldBound(&table) {
		return s24.MDTModeExtensionIEIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s24.MDTModeExtensionIEIEContainerValueCodec {
		sealed := s24.MDTModeExtensionIEIEContainerValueCodec{}
		*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.MDTModeExtensionIEIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.MDTModeExtensionIEIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.MDTModeExtensionIEIEField
					if err := s24.BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(&sealed) = func(fields s24.MDTModeExtensionIEIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s24.BridgeMDTModeExtensionIEIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldCapture(&sealed) = func(v s24.MDTModeExtensionIEIEContainer, options aper.DecodeState) (s24.MDTModeExtensionIEIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldCompare(&sealed) = func(v s24.MDTModeExtensionIEIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{MMEConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func MMEConfigurationUpdateAcknowledgeIEValueIETableCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable, bounds aper.ListBounds) s23.MMEConfigurationUpdateAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&table) {
		return s23.MMEConfigurationUpdateAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.MMEConfigurationUpdateAcknowledgeIEContainerValueCodec {
		sealed := s23.MMEConfigurationUpdateAcknowledgeIEContainerValueCodec{}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEConfigurationUpdateAcknowledgeIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.MMEConfigurationUpdateAcknowledgeIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.MMEConfigurationUpdateAcknowledgeIEField
					if err := s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.MMEConfigurationUpdateAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCapture(&sealed) = func(v s22.MMEConfigurationUpdateAcknowledgeIEContainer, options aper.DecodeState) (s22.MMEConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCompare(&sealed) = func(v s22.MMEConfigurationUpdateAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueIETableCodec constructs the ProtocolIE-Container {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueIETableCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s23.MMEConfigurationUpdateFailureIEContainerValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateFailureIEValueIETableFieldBound(&table) {
		return s23.MMEConfigurationUpdateFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.MMEConfigurationUpdateFailureIEContainerValueCodec {
		sealed := s23.MMEConfigurationUpdateFailureIEContainerValueCodec{}
		*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.MMEConfigurationUpdateFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.MMEConfigurationUpdateFailureIEField
					if err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.MMEConfigurationUpdateFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEContainer, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueIETableCodec constructs the ProtocolIE-Container {{MMEStatusTransferIEs}} codec of TS 36.413.
func MMEStatusTransferIEValueIETableCodec(table s00.MMEStatusTransferIEValueIETable, bounds aper.ListBounds) s22.MMEStatusTransferIEContainerValueCodec {
	if !*s00.BridgeMMEStatusTransferIEValueIETableFieldBound(&table) {
		return s22.MMEStatusTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.MMEStatusTransferIEContainerValueCodec {
		sealed := s22.MMEStatusTransferIEContainerValueCodec{}
		*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEStatusTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.MMEStatusTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.MMEStatusTransferIEField
					if err := s22.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.MMEStatusTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s22.MMEStatusTransferIEContainer, options aper.DecodeState) (s22.MMEStatusTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s22.MMEStatusTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{NASNonDeliveryIndication-IEs}} codec of TS 36.413.
func NASNonDeliveryIndicationIEValueIETableCodec(table s00.NASNonDeliveryIndicationIEValueIETable, bounds aper.ListBounds) s19.NASNonDeliveryIndicationIEContainerValueCodec {
	if !*s00.BridgeNASNonDeliveryIndicationIEValueIETableFieldBound(&table) {
		return s19.NASNonDeliveryIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s19.NASNonDeliveryIndicationIEContainerValueCodec {
		sealed := s19.NASNonDeliveryIndicationIEContainerValueCodec{}
		*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.NASNonDeliveryIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.NASNonDeliveryIndicationIEField
					if err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s19.NASNonDeliveryIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s19.NASNonDeliveryIndicationIEContainer, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s19.NASNonDeliveryIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABReleaseItemBearerRelCompIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable) s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABReleaseItemBearerRelCompIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec{}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList(value), err
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(&codec))(s16.ERABReleaseItemBearerRelCompIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABSetupItemBearerSUResIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListCodec(table s00.ERABSetupItemBearerSUResIEValueIETable) s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSetupItemBearerSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec{}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList(value), err
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemBearerSUResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABSetupItemCtxtSUResIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec{}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList(value), err
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable) s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModIndIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec{}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList(value), err
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s17.ERABToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABToBeModifiedItemBearerModReqIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModReqIEValueIETable) ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeModifiedItemBearerModReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABToBeSwitchedULItemIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeSwitchedULItemIEValueIETable) s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeSwitchedULItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(&codec))(s17.ERABToBeSwitchedULItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABUsageReportItemIEs}} codec of TS 36.413.
func ERABUsageReportItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABUsageReportItemIEValueIETable) s17.ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABUsageReportItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s17.ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s17.ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s17.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABUsageReportItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABUsageReportItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s17.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABUsageReportItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(&codec))(s17.ERABUsageReportItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABUsageReportItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s17.ERABUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABUsageReportItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABUsageReportItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverCancelAcknowledgeIEs}} codec of TS 36.413.
func HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.HandoverCancelAcknowledgeIEValueIETable) s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverCancelAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList(value), err
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.HandoverCancelAcknowledgeIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverCancelIEs}} codec of TS 36.413.
func HandoverCancelIEValueProtocolErrorIEContainerListCodec(table s00.HandoverCancelIEValueIETable) s18.HandoverCancelIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverCancelIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.HandoverCancelIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s18.HandoverCancelIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s18.HandoverCancelIEValueProtocolErrorIEContainerListValueCodec{}
		*s18.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.HandoverCancelIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s18.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s18.HandoverCancelIEValueProtocolErrorIEContainerList(value), err
		}
		*s18.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.HandoverCancelIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeHandoverCancelIEContainerValueCodecFieldEncode(&codec))(s18.HandoverCancelIEContainer(value), fresh, budget)
		}
		*s18.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.HandoverCancelIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s18.HandoverCancelIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.HandoverCancelIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeHandoverCancelIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverFailureIEs}} codec of TS 36.413.
func HandoverFailureIEValueProtocolErrorIEContainerListCodec(table s00.HandoverFailureIEValueIETable) s22.HandoverFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s22.HandoverFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.HandoverFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverFailureIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s22.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverFailureIEValueProtocolErrorIEContainerList(value), err
		}
		*s22.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverFailureIEContainerValueCodecFieldEncode(&codec))(s22.HandoverFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s22.HandoverFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeHandoverFailureIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverPreparationFailureIEs}} codec of TS 36.413.
func HandoverPreparationFailureIEValueProtocolErrorIEContainerListCodec(table s00.HandoverPreparationFailureIEValueIETable) s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverPreparationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerList(value), err
		}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(&codec))(s22.HandoverPreparationFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{InitialContextSetupFailureIEs}} codec of TS 36.413.
func InitialContextSetupFailureIEValueProtocolErrorIEContainerListCodec(table s00.InitialContextSetupFailureIEValueIETable) s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := InitialContextSetupFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerList(value), err
		}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(&codec))(s22.InitialContextSetupFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{LocationReportingFailureIndicationIEs}} codec of TS 36.413.
func LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListCodec(table s00.LocationReportingFailureIndicationIEValueIETable) s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := LocationReportingFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList(value), err
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s18.LocationReportingFailureIndicationIEContainer(value), fresh, budget)
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MDTMode-ExtensionIE}} codec of TS 36.413.
func MDTModeExtensionIEIEValueProtocolErrorIEContainerListCodec(table s00.MDTModeExtensionIEIEValueIETable) s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
	codec := MDTModeExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerList(value), err
		}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(&codec))(s24.MDTModeExtensionIEIEContainer(value), fresh, budget)
		}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable) s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEConfigurationUpdateAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList(value), err
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.MMEConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable) s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList(value), err
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s23.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEStatusTransferIEs}} codec of TS 36.413.
func MMEStatusTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEStatusTransferIEValueIETable) s22.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s22.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEStatusTransferIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.MMEStatusTransferIEValueProtocolErrorIEContainerList(value), err
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.MMEStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&codec))(s22.MMEStatusTransferIEContainer(value), fresh, budget)
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.MMEStatusTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s22.MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.MMEStatusTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{NASNonDeliveryIndication-IEs}} codec of TS 36.413.
func NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListCodec(table s00.NASNonDeliveryIndicationIEValueIETable) s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := NASNonDeliveryIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList(value), err
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s19.NASNonDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABNotToBeModifiedItemBearerModIndIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
	codec := s24.ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
		sealed := s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec{}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList(value), err
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s16.ERABNotToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s24.BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABReleaseItemBearerRelCompIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable, bounds aper.ListBounds) s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec {
	codec := ERABReleaseItemBearerRelCompIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec {
		sealed := s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec{}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList(value), err
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(&codec))(s16.ERABReleaseItemBearerRelCompIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, options aper.DecodeState) (s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABSetupItemBearerSUResIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABSetupItemBearerSUResIEValueProtocolIEContainerListCodec(table s00.ERABSetupItemBearerSUResIEValueIETable, bounds aper.ListBounds) s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec {
	codec := ERABSetupItemBearerSUResIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec {
		sealed := s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec{}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerList(value), err
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemBearerSUResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, options aper.DecodeState) (s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABSetupItemCtxtSUResIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABSetupItemCtxtSUResIEValueProtocolIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable, bounds aper.ListBounds) s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec {
		sealed := s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec{}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList(value), err
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, options aper.DecodeState) (s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeModifiedItemBearerModIndIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModIndIEValueIETableCodec(table, bounds)
	if *s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
		sealed := s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec{}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, error) {
			value, err := (*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList(value), err
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s17.ERABToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, options aper.DecodeState) (s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeModifiedItemBearerModReqIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModReqIEValueIETable, bounds aper.ListBounds) ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModReqIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeModifiedItemBearerModReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// ERABToBeSwitchedULItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeSwitchedULItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABToBeSwitchedULItemIEValueProtocolIEContainerListCodec(table s00.ERABToBeSwitchedULItemIEValueIETable, bounds aper.ListBounds) s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeSwitchedULItemIEValueIETableCodec(table, bounds)
	if *s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec {
		sealed := s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec{}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, error) {
			value, err := (*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerList(value), err
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(&codec))(s17.ERABToBeSwitchedULItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, options aper.DecodeState) (s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABUsageReportItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABUsageReportItemIEValueProtocolIEContainerListCodec(table s00.ERABUsageReportItemIEValueIETable, bounds aper.ListBounds) s17.ERABUsageReportItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABUsageReportItemIEValueIETableCodec(table, bounds)
	if *s17.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.ERABUsageReportItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s17.ERABUsageReportItemIEValueProtocolIEContainerListValueCodec {
		sealed := s17.ERABUsageReportItemIEValueProtocolIEContainerListValueCodec{}
		*s17.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABUsageReportItemIEValueProtocolIEContainerList, error) {
			value, err := (*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.ERABUsageReportItemIEValueProtocolIEContainerList(value), err
		}
		*s17.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.ERABUsageReportItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(&codec))(s17.ERABUsageReportItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.ERABUsageReportItemIEValueProtocolIEContainerList, options aper.DecodeState) (s17.ERABUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s17.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.ERABUsageReportItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverCancelAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverCancelAcknowledgeIEValueProtocolIEContainerListCodec(table s00.HandoverCancelAcknowledgeIEValueIETable, bounds aper.ListBounds) s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := HandoverCancelAcknowledgeIEValueIETableCodec(table, bounds)
	if *s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec {
		sealed := s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, error) {
			value, err := (*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerList(value), err
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.HandoverCancelAcknowledgeIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverCancelIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverCancelIEValueProtocolIEContainerListCodec(table s00.HandoverCancelIEValueIETable, bounds aper.ListBounds) s18.HandoverCancelIEValueProtocolIEContainerListValueCodec {
	codec := HandoverCancelIEValueIETableCodec(table, bounds)
	if *s18.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.HandoverCancelIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s18.HandoverCancelIEValueProtocolIEContainerListValueCodec {
		sealed := s18.HandoverCancelIEValueProtocolIEContainerListValueCodec{}
		*s18.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.HandoverCancelIEValueProtocolIEContainerList, error) {
			value, err := (*s18.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s18.HandoverCancelIEValueProtocolIEContainerList(value), err
		}
		*s18.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.HandoverCancelIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeHandoverCancelIEContainerValueCodecFieldEncode(&codec))(s18.HandoverCancelIEContainer(value), fresh, budget)
		}
		*s18.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.HandoverCancelIEValueProtocolIEContainerList, options aper.DecodeState) (s18.HandoverCancelIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s18.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.HandoverCancelIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverFailureIEValueProtocolIEContainerListCodec(table s00.HandoverFailureIEValueIETable, bounds aper.ListBounds) s22.HandoverFailureIEValueProtocolIEContainerListValueCodec {
	codec := HandoverFailureIEValueIETableCodec(table, bounds)
	if *s22.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverFailureIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s22.HandoverFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s22.HandoverFailureIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverFailureIEValueProtocolIEContainerList, error) {
			value, err := (*s22.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverFailureIEValueProtocolIEContainerList(value), err
		}
		*s22.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverFailureIEContainerValueCodecFieldEncode(&codec))(s22.HandoverFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s22.HandoverFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s22.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverPreparationFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverPreparationFailureIEValueProtocolIEContainerListCodec(table s00.HandoverPreparationFailureIEValueIETable, bounds aper.ListBounds) s22.HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec {
	codec := HandoverPreparationFailureIEValueIETableCodec(table, bounds)
	if *s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s22.HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s22.HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.HandoverPreparationFailureIEValueProtocolIEContainerList, error) {
			value, err := (*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.HandoverPreparationFailureIEValueProtocolIEContainerList(value), err
		}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.HandoverPreparationFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(&codec))(s22.HandoverPreparationFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.HandoverPreparationFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s22.HandoverPreparationFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.HandoverPreparationFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {InitialContextSetupFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func InitialContextSetupFailureIEValueProtocolIEContainerListCodec(table s00.InitialContextSetupFailureIEValueIETable, bounds aper.ListBounds) s22.InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec {
	codec := InitialContextSetupFailureIEValueIETableCodec(table, bounds)
	if *s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s22.InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s22.InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.InitialContextSetupFailureIEValueProtocolIEContainerList, error) {
			value, err := (*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.InitialContextSetupFailureIEValueProtocolIEContainerList(value), err
		}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.InitialContextSetupFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(&codec))(s22.InitialContextSetupFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.InitialContextSetupFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s22.InitialContextSetupFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.InitialContextSetupFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {LocationReportingFailureIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func LocationReportingFailureIndicationIEValueProtocolIEContainerListCodec(table s00.LocationReportingFailureIndicationIEValueIETable, bounds aper.ListBounds) s19.LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec {
	codec := LocationReportingFailureIndicationIEValueIETableCodec(table, bounds)
	if *s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s19.LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s19.LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.LocationReportingFailureIndicationIEValueProtocolIEContainerList, error) {
			value, err := (*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s19.LocationReportingFailureIndicationIEValueProtocolIEContainerList(value), err
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.LocationReportingFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s18.LocationReportingFailureIndicationIEContainer(value), fresh, budget)
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.LocationReportingFailureIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s19.LocationReportingFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.LocationReportingFailureIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MDTMode-ExtensionIE} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MDTModeExtensionIEIEValueProtocolIEContainerListCodec(table s00.MDTModeExtensionIEIEValueIETable, bounds aper.ListBounds) s24.MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec {
	codec := MDTModeExtensionIEIEValueIETableCodec(table, bounds)
	if *s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s24.MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec {
		sealed := s24.MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.MDTModeExtensionIEIEValueProtocolIEContainerList, error) {
			value, err := (*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.MDTModeExtensionIEIEValueProtocolIEContainerList(value), err
		}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.MDTModeExtensionIEIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(&codec))(s24.MDTModeExtensionIEIEContainer(value), fresh, budget)
		}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.MDTModeExtensionIEIEValueProtocolIEContainerList, options aper.DecodeState) (s24.MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.MDTModeExtensionIEIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationUpdateAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable, bounds aper.ListBounds) s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := MMEConfigurationUpdateAcknowledgeIEValueIETableCodec(table, bounds)
	if *s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, error) {
			value, err := (*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList(value), err
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.MMEConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationUpdateFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEConfigurationUpdateFailureIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, bounds)
	if *s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, error) {
			value, err := (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList(value), err
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s23.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEStatusTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEStatusTransferIEValueProtocolIEContainerListCodec(table s00.MMEStatusTransferIEValueIETable, bounds aper.ListBounds) s22.MMEStatusTransferIEValueProtocolIEContainerListValueCodec {
	codec := MMEStatusTransferIEValueIETableCodec(table, bounds)
	if *s22.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.MMEStatusTransferIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s22.MMEStatusTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s22.MMEStatusTransferIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEStatusTransferIEValueProtocolIEContainerList, error) {
			value, err := (*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.MMEStatusTransferIEValueProtocolIEContainerList(value), err
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.MMEStatusTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&codec))(s22.MMEStatusTransferIEContainer(value), fresh, budget)
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.MMEStatusTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s22.MMEStatusTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.MMEStatusTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {NASNonDeliveryIndication-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func NASNonDeliveryIndicationIEValueProtocolIEContainerListCodec(table s00.NASNonDeliveryIndicationIEValueIETable, bounds aper.ListBounds) s19.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
	codec := NASNonDeliveryIndicationIEValueIETableCodec(table, bounds)
	if *s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s19.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s19.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, error) {
			value, err := (*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList(value), err
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s19.NASNonDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eRABNotToBeModifiedItemBearerModIndIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.ERABNotToBeModifiedItemBearerModIndIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.ERABNotToBeModifiedItemBearerModIndIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABReleaseItemBearerRelCompIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.ERABReleaseItemBearerRelCompIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.ERABReleaseItemBearerRelCompIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEField(v *s16.ERABReleaseItemBearerRelCompIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s16.BridgeERABReleaseItemBearerRelCompIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s16.BridgeERABReleaseItemBearerRelCompIEFieldFieldReplay(v), *s16.BridgeERABReleaseItemBearerRelCompIEFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEField(v *s16.ERABReleaseItemBearerRelCompIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeERABReleaseItemBearerRelCompIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s16.BridgeERABReleaseItemBearerRelCompIEFieldFieldReplay(v), *s16.BridgeERABReleaseItemBearerRelCompIEFieldFieldWithoutReplay(v))
}

// eRABSetupItemBearerSUResIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.ERABSetupItemBearerSUResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.ERABSetupItemBearerSUResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEField(v *s16.ERABSetupItemBearerSUResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s16.BridgeERABSetupItemBearerSUResIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s16.BridgeERABSetupItemBearerSUResIEFieldFieldReplay(v), *s16.BridgeERABSetupItemBearerSUResIEFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEField(v *s16.ERABSetupItemBearerSUResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeERABSetupItemBearerSUResIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s16.BridgeERABSetupItemBearerSUResIEFieldFieldReplay(v), *s16.BridgeERABSetupItemBearerSUResIEFieldFieldWithoutReplay(v))
}

// eRABSetupItemCtxtSUResIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.ERABSetupItemCtxtSUResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.ERABSetupItemCtxtSUResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEField(v *s16.ERABSetupItemCtxtSUResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s16.BridgeERABSetupItemCtxtSUResIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s16.BridgeERABSetupItemCtxtSUResIEFieldFieldReplay(v), *s16.BridgeERABSetupItemCtxtSUResIEFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(v *s16.ERABSetupItemCtxtSUResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeERABSetupItemCtxtSUResIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s16.BridgeERABSetupItemCtxtSUResIEFieldFieldReplay(v), *s16.BridgeERABSetupItemCtxtSUResIEFieldFieldWithoutReplay(v))
}

// eRABToBeModifyItemBearerModReqExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeModifyItemBearerModReqExtIEsValue].
type ERABToBeModifyItemBearerModReqExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s21.ERABToBeModifyItemBearerModReqExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s21.ERABToBeModifyItemBearerModReqExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionField(v *s21.ERABToBeModifyItemBearerModReqExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s21.BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldReplay(v), *s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionField(v *s21.ERABToBeModifyItemBearerModReqExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s21.BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldReplay(v), *s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldWithoutReplay(v))
}

// eRABToBeModifiedItemBearerModIndIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeModifiedItemBearerModIndIEValue].
type ERABToBeModifiedItemBearerModIndIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s17.ERABToBeModifiedItemBearerModIndIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s17.ERABToBeModifiedItemBearerModIndIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(v *s17.ERABToBeModifiedItemBearerModIndIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s17.BridgeERABToBeModifiedItemBearerModIndIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s17.BridgeERABToBeModifiedItemBearerModIndIEFieldFieldReplay(v), *s17.BridgeERABToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v))
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(v *s17.ERABToBeModifiedItemBearerModIndIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s17.BridgeERABToBeModifiedItemBearerModIndIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s17.BridgeERABToBeModifiedItemBearerModIndIEFieldFieldReplay(v), *s17.BridgeERABToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v))
}

// eRABToBeModifiedItemBearerModReqIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeModifiedItemBearerModReqIEValue].
type ERABToBeModifiedItemBearerModReqIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABToBeModifiedItemBearerModReqIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABToBeModifiedItemBearerModReqIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEField(v *ERABToBeModifiedItemBearerModReqIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEField(v *ERABToBeModifiedItemBearerModReqIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABToBeSwitchedULItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSwitchedULItemIEValue].
type ERABToBeSwitchedULItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s17.ERABToBeSwitchedULItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s17.ERABToBeSwitchedULItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEField(v *s17.ERABToBeSwitchedULItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s17.BridgeERABToBeSwitchedULItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s17.BridgeERABToBeSwitchedULItemIEFieldFieldReplay(v), *s17.BridgeERABToBeSwitchedULItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEField(v *s17.ERABToBeSwitchedULItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s17.BridgeERABToBeSwitchedULItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s17.BridgeERABToBeSwitchedULItemIEFieldFieldReplay(v), *s17.BridgeERABToBeSwitchedULItemIEFieldFieldWithoutReplay(v))
}

// eRABUsageReportItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABUsageReportItemIEValue].
type ERABUsageReportItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s17.ERABUsageReportItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s17.ERABUsageReportItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEField(v *s17.ERABUsageReportItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s17.BridgeERABUsageReportItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s17.BridgeERABUsageReportItemIEFieldFieldReplay(v), *s17.BridgeERABUsageReportItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABUsageReportItemIEValueCompareS1APProtocolIEField(v *s17.ERABUsageReportItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s17.BridgeERABUsageReportItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s17.BridgeERABUsageReportItemIEFieldFieldReplay(v), *s17.BridgeERABUsageReportItemIEFieldFieldWithoutReplay(v))
}

// handoverCancelIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverCancelIEValue].
type HandoverCancelIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s18.HandoverCancelIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s18.HandoverCancelIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverCancelIEValueCaptureS1APProtocolIEField(v *s18.HandoverCancelIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s18.BridgeHandoverCancelIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s18.BridgeHandoverCancelIEFieldFieldReplay(v), *s18.BridgeHandoverCancelIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverCancelIEValueCompareS1APProtocolIEField(v *s18.HandoverCancelIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s18.BridgeHandoverCancelIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s18.BridgeHandoverCancelIEFieldFieldReplay(v), *s18.BridgeHandoverCancelIEFieldFieldWithoutReplay(v))
}

// handoverCancelAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.HandoverCancelAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.HandoverCancelAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEField(v *s22.HandoverCancelAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeHandoverCancelAcknowledgeIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeHandoverCancelAcknowledgeIEFieldFieldReplay(v), *s22.BridgeHandoverCancelAcknowledgeIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEField(v *s22.HandoverCancelAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeHandoverCancelAcknowledgeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeHandoverCancelAcknowledgeIEFieldFieldReplay(v), *s22.BridgeHandoverCancelAcknowledgeIEFieldFieldWithoutReplay(v))
}

// handoverFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverFailureIEValue].
type HandoverFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.HandoverFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.HandoverFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverFailureIEValueCaptureS1APProtocolIEField(v *s22.HandoverFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeHandoverFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeHandoverFailureIEFieldFieldReplay(v), *s22.BridgeHandoverFailureIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverFailureIEValueCompareS1APProtocolIEField(v *s22.HandoverFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeHandoverFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeHandoverFailureIEFieldFieldReplay(v), *s22.BridgeHandoverFailureIEFieldFieldWithoutReplay(v))
}

// handoverPreparationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverPreparationFailureIEValue].
type HandoverPreparationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.HandoverPreparationFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.HandoverPreparationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEField(v *s22.HandoverPreparationFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeHandoverPreparationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeHandoverPreparationFailureIEFieldFieldReplay(v), *s22.BridgeHandoverPreparationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEField(v *s22.HandoverPreparationFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeHandoverPreparationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeHandoverPreparationFailureIEFieldFieldReplay(v), *s22.BridgeHandoverPreparationFailureIEFieldFieldWithoutReplay(v))
}

// initialContextSetupFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[InitialContextSetupFailureIEValue].
type InitialContextSetupFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.InitialContextSetupFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.InitialContextSetupFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEField(v *s22.InitialContextSetupFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeInitialContextSetupFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeInitialContextSetupFailureIEFieldFieldReplay(v), *s22.BridgeInitialContextSetupFailureIEFieldFieldWithoutReplay(v))
}
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEField(v *s22.InitialContextSetupFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeInitialContextSetupFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeInitialContextSetupFailureIEFieldFieldReplay(v), *s22.BridgeInitialContextSetupFailureIEFieldFieldWithoutReplay(v))
}

// locationReportingFailureIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s18.LocationReportingFailureIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s18.LocationReportingFailureIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEField(v *s18.LocationReportingFailureIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s18.BridgeLocationReportingFailureIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s18.BridgeLocationReportingFailureIndicationIEFieldFieldReplay(v), *s18.BridgeLocationReportingFailureIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEField(v *s18.LocationReportingFailureIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s18.BridgeLocationReportingFailureIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s18.BridgeLocationReportingFailureIndicationIEFieldFieldReplay(v), *s18.BridgeLocationReportingFailureIndicationIEFieldFieldWithoutReplay(v))
}

// mMEConfigurationUpdateAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.MMEConfigurationUpdateAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.MMEConfigurationUpdateAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(v *s22.MMEConfigurationUpdateAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldReplay(v), *s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v))
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(v *s22.MMEConfigurationUpdateAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldReplay(v), *s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v))
}

// mMEConfigurationUpdateFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s23.MMEConfigurationUpdateFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s23.MMEConfigurationUpdateFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(v *s23.MMEConfigurationUpdateFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgeMMEConfigurationUpdateFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgeMMEConfigurationUpdateFailureIEFieldFieldReplay(v), *s23.BridgeMMEConfigurationUpdateFailureIEFieldFieldWithoutReplay(v))
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v *s23.MMEConfigurationUpdateFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgeMMEConfigurationUpdateFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgeMMEConfigurationUpdateFailureIEFieldFieldReplay(v), *s23.BridgeMMEConfigurationUpdateFailureIEFieldFieldWithoutReplay(v))
}

// mMEStatusTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEStatusTransferIEValue].
type MMEStatusTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s21.MMEStatusTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s21.MMEStatusTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEField(v *s22.MMEStatusTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s21.BridgeMMEStatusTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeMMEStatusTransferIEFieldFieldReplay(v), *s22.BridgeMMEStatusTransferIEFieldFieldWithoutReplay(v))
}
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIEField(v *s22.MMEStatusTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s21.BridgeMMEStatusTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeMMEStatusTransferIEFieldFieldReplay(v), *s22.BridgeMMEStatusTransferIEFieldFieldWithoutReplay(v))
}

// nASNonDeliveryIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.NASNonDeliveryIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.NASNonDeliveryIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEField(v *s19.NASNonDeliveryIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s19.BridgeNASNonDeliveryIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s19.BridgeNASNonDeliveryIndicationIEFieldFieldReplay(v), *s19.BridgeNASNonDeliveryIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEField(v *s19.NASNonDeliveryIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s19.BridgeNASNonDeliveryIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s19.BridgeNASNonDeliveryIndicationIEFieldFieldReplay(v), *s19.BridgeNASNonDeliveryIndicationIEFieldFieldWithoutReplay(v))
}

// ERABToBeModifiedListBearerModReqAPERValue is the concrete APERValue[ERABToBeModifiedListBearerModReq].
type ERABToBeModifiedListBearerModReqAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeModifiedListBearerModReq

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedListBearerModReqAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedListBearerModReqAPERValue) WithoutReplay() ERABToBeModifiedListBearerModReqAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModReqAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModReq].
type ERABToBeModifiedItemBearerModReqAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeModifiedItemBearerModReq

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModReqAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModReqAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModReqAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelAcknowledgeAPERValue is the concrete APERValue[HandoverCancelAcknowledge].
type HandoverCancelAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverCancelAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelAcknowledgeAPERValue) WithoutReplay() HandoverCancelAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelAPERValue is the concrete APERValue[HandoverCancel].
type HandoverCancelAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverCancel

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelAPERValue) WithoutReplay() HandoverCancelAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverFailureAPERValue is the concrete APERValue[HandoverFailure].
type HandoverFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverFailureAPERValue) WithoutReplay() HandoverFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverPreparationFailureAPERValue is the concrete APERValue[HandoverPreparationFailure].
type HandoverPreparationFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverPreparationFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverPreparationFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverPreparationFailureAPERValue) WithoutReplay() HandoverPreparationFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupFailureAPERValue is the concrete APERValue[InitialContextSetupFailure].
type InitialContextSetupFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   InitialContextSetupFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupFailureAPERValue) WithoutReplay() InitialContextSetupFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingFailureIndicationAPERValue is the concrete APERValue[LocationReportingFailureIndication].
type LocationReportingFailureIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   LocationReportingFailureIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingFailureIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingFailureIndicationAPERValue) WithoutReplay() LocationReportingFailureIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateAcknowledgeAPERValue is the concrete APERValue[MMEConfigurationUpdateAcknowledge].
type MMEConfigurationUpdateAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEConfigurationUpdateAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateAcknowledgeAPERValue) WithoutReplay() MMEConfigurationUpdateAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateFailureAPERValue is the concrete APERValue[MMEConfigurationUpdateFailure].
type MMEConfigurationUpdateFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEConfigurationUpdateFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateFailureAPERValue) WithoutReplay() MMEConfigurationUpdateFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferAPERValue is the concrete APERValue[MMEStatusTransfer].
type MMEStatusTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEStatusTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferAPERValue) WithoutReplay() MMEStatusTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASNonDeliveryIndicationAPERValue is the concrete APERValue[NASNonDeliveryIndication].
type NASNonDeliveryIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   NASNonDeliveryIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASNonDeliveryIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASNonDeliveryIndicationAPERValue) WithoutReplay() NASNonDeliveryIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APERABIEContainerList(v *s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APERABIEContainerList(v *s16.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APERABIEContainerList(v *s16.ERABSetupItemBearerSUResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemBearerSUResIEValueCompareS1APERABIEContainerList(v *s16.ERABSetupItemBearerSUResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APERABIEContainerList(v *s17.ERABSetupItemCtxtSUResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APERABIEContainerList(v *s17.ERABSetupItemCtxtSUResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APERABIEContainerList(v *s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APERABIEContainerList(v *s17.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList].
type ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, error)
	encode  func(ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) New(value ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABToBeModifiedItemBearerModReqIEs}} of TS 36.413: a list of information element fields.
type ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList []ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer

func BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APERABIEContainerList(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APERABIEContainerList(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APERABIEContainerList(v *s17.ERABToBeSwitchedULItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedULItemIEValueCompareS1APERABIEContainerList(v *s17.ERABToBeSwitchedULItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABUsageReportItemIEValueCaptureS1APERABIEContainerList(v *s17.ERABUsageReportItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABUsageReportItemIEValueCompareS1APERABIEContainerList(v *s17.ERABUsageReportItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APERABIEContainerList(v *s22.HandoverCancelAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APERABIEContainerList(v *s22.HandoverCancelAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelIEValueCaptureS1APERABIEContainerList(v *s18.HandoverCancelIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCancelIEValueCompareS1APERABIEContainerList(v *s18.HandoverCancelIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverFailureIEValueCaptureS1APERABIEContainerList(v *s22.HandoverFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverFailureIEValueCompareS1APERABIEContainerList(v *s22.HandoverFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverPreparationFailureIEValueCaptureS1APERABIEContainerList(v *s22.HandoverPreparationFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverPreparationFailureIEValueCompareS1APERABIEContainerList(v *s22.HandoverPreparationFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialContextSetupFailureIEValueCaptureS1APERABIEContainerList(v *s22.InitialContextSetupFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialContextSetupFailureIEValueCompareS1APERABIEContainerList(v *s22.InitialContextSetupFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APERABIEContainerList(v *s19.LocationReportingFailureIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportingFailureIndicationIEValueCompareS1APERABIEContainerList(v *s19.LocationReportingFailureIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// mDTModeExtensionIEIEValueProtocolOpenValue is the concrete protocolOpenValue[MDTModeExtensionIEIEValue].
type MDTModeExtensionIEIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s24.MDTModeExtensionIEIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s24.MDTModeExtensionIEIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMDTModeExtensionIEIEValueCaptureS1APERABIEContainerList(v *s24.MDTModeExtensionIEIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMDTModeExtensionIEIEValueCompareS1APERABIEContainerList(v *s24.MDTModeExtensionIEIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APERABIEContainerList(v *s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APERABIEContainerList(v *s23.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(v *s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(v *s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEStatusTransferIEValueCaptureS1APERABIEContainerList(v *s22.MMEStatusTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEStatusTransferIEValueCompareS1APERABIEContainerList(v *s22.MMEStatusTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APERABIEContainerList(v *s19.NASNonDeliveryIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNASNonDeliveryIndicationIEValueCompareS1APERABIEContainerList(v *s19.NASNonDeliveryIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeModifiedItemBearerModReqIEFieldValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModReqIEField].
type ERABToBeModifiedItemBearerModReqIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEField, error)
	encode  func(ERABToBeModifiedItemBearerModReqIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModReqIEField, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEField, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModReqIEFieldValueCodec) New(value ERABToBeModifiedItemBearerModReqIEField) (ERABToBeModifiedItemBearerModReqIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModReqIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModReqIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModReqIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModReqIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModReqIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModReqIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModReqIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModReqIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModReqIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModReqIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModReqIEFieldValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModReqIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModReqIEFieldValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModReqIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModReqIEFieldValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModReqIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEField(v *s24.MDTModeExtensionIEIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s24.BridgeMDTModeExtensionIEIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s24.BridgeMDTModeExtensionIEIEFieldFieldReplay(v), *s24.BridgeMDTModeExtensionIEIEFieldFieldWithoutReplay(v))
}
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEField(v *s24.MDTModeExtensionIEIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s24.BridgeMDTModeExtensionIEIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s24.BridgeMDTModeExtensionIEIEFieldFieldReplay(v), *s24.BridgeMDTModeExtensionIEIEFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEContainer(v *s16.ERABReleaseItemBearerRelCompIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEContainer(v *s16.ERABReleaseItemBearerRelCompIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEContainer(v *s16.ERABSetupItemBearerSUResIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEContainer(v *s16.ERABSetupItemBearerSUResIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainer(v *s16.ERABSetupItemCtxtSUResIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainer(v *s16.ERABSetupItemCtxtSUResIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainer(v *s17.ERABToBeModifiedItemBearerModIndIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainer(v *s17.ERABToBeModifiedItemBearerModIndIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeModifiedItemBearerModReqIEContainerValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModReqIEContainer].
type ERABToBeModifiedItemBearerModReqIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEContainer, error)
	encode  func(ERABToBeModifiedItemBearerModReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModReqIEContainer, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEContainer, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModReqIEContainerValueCodec) New(value ERABToBeModifiedItemBearerModReqIEContainer) (ERABToBeModifiedItemBearerModReqIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModReqIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModReqIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModReqIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModReqIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModReqIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModReqIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModReqIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModReqIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModReqIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModReqIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModReqIEContainerValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModReqIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModReqIEContainerValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModReqIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModReqIEContainerValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModReqIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEContainer(v *ERABToBeModifiedItemBearerModReqIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEContainer(v *ERABToBeModifiedItemBearerModReqIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEContainer(v *s17.ERABToBeSwitchedULItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEContainer(v *s17.ERABToBeSwitchedULItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEContainer(v *s17.ERABUsageReportItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABUsageReportItemIEValueCompareS1APProtocolIEContainer(v *s17.ERABUsageReportItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEContainer(v *s24.MDTModeExtensionIEIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEContainer(v *s24.MDTModeExtensionIEIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PrivateMessageIEsValuePrivateIEFieldValueCodec is the concrete ValueCodec[PrivateMessageIEsValuePrivateIEField].
type PrivateMessageIEsValuePrivateIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PrivateMessageIEsValuePrivateIEField, error)
	encode  func(PrivateMessageIEsValuePrivateIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PrivateMessageIEsValuePrivateIEField, aper.DecodeState) (PrivateMessageIEsValuePrivateIEField, aper.Snapshot)
	compare func(PrivateMessageIEsValuePrivateIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PrivateMessageIEsValuePrivateIEFieldValueCodec) New(value PrivateMessageIEsValuePrivateIEField) (PrivateMessageIEsValuePrivateIEFieldAPERValue, error) {
	if c.encode == nil {
		return PrivateMessageIEsValuePrivateIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateMessageIEsValuePrivateIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivateMessageIEsValuePrivateIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PrivateMessageIEsValuePrivateIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PrivateMessageIEsValuePrivateIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PrivateMessageIEsValuePrivateIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PrivateMessageIEsValuePrivateIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PrivateMessageIEsValuePrivateIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PrivateMessageIEsValuePrivateIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PrivateMessageIEsValuePrivateIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PrivateMessageIEsValuePrivateIEFieldValueCodec) EncodeAPER(value PrivateMessageIEsValuePrivateIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PrivateMessageIEsValuePrivateIEFieldValueCodec) encodeBudgetValue(value PrivateMessageIEsValuePrivateIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PrivateMessageIEsValuePrivateIEFieldValueCodec) encodeChanged(value PrivateMessageIEsValuePrivateIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PrivateMessageIEsValuePrivateIEContainerValueCodec is the concrete ValueCodec[PrivateMessageIEsValuePrivateIEContainer].
type PrivateMessageIEsValuePrivateIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PrivateMessageIEsValuePrivateIEContainer, error)
	encode  func(PrivateMessageIEsValuePrivateIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PrivateMessageIEsValuePrivateIEContainer, aper.DecodeState) (PrivateMessageIEsValuePrivateIEContainer, aper.Snapshot)
	compare func(PrivateMessageIEsValuePrivateIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PrivateMessageIEsValuePrivateIEContainerValueCodec) New(value PrivateMessageIEsValuePrivateIEContainer) (PrivateMessageIEsValuePrivateIEContainerAPERValue, error) {
	if c.encode == nil {
		return PrivateMessageIEsValuePrivateIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateMessageIEsValuePrivateIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivateMessageIEsValuePrivateIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PrivateMessageIEsValuePrivateIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PrivateMessageIEsValuePrivateIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PrivateMessageIEsValuePrivateIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PrivateMessageIEsValuePrivateIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PrivateMessageIEsValuePrivateIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PrivateMessageIEsValuePrivateIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PrivateMessageIEsValuePrivateIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PrivateMessageIEsValuePrivateIEContainerValueCodec) EncodeAPER(value PrivateMessageIEsValuePrivateIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PrivateMessageIEsValuePrivateIEContainerValueCodec) encodeBudgetValue(value PrivateMessageIEsValuePrivateIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PrivateMessageIEsValuePrivateIEContainerValueCodec) encodeChanged(value PrivateMessageIEsValuePrivateIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolErrorIEContainerList(v *s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolErrorIEContainerList(v *s16.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolErrorIEContainerList(v *s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolErrorIEContainerList(v *s16.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolErrorIEContainerList(v *s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolErrorIEContainerList(v *s17.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolErrorIEContainerList(v *s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolErrorIEContainerList(v *s17.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList].
type ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) New(value ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABToBeModifiedItemBearerModReqIEs}} of TS 36.413: a list of information element fields.
type ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList []ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer

func BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolErrorIEContainerList(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolErrorIEContainerList(v *s17.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABUsageReportItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s17.ERABUsageReportItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABUsageReportItemIEValueCompareS1APProtocolErrorIEContainerList(v *s17.ERABUsageReportItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *s22.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelIEValueCaptureS1APProtocolErrorIEContainerList(v *s18.HandoverCancelIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCancelIEValueCompareS1APProtocolErrorIEContainerList(v *s18.HandoverCancelIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s22.HandoverFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s22.HandoverFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s22.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s22.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s19.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolErrorIEContainerList(v *s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(v *s24.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s22.MMEStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s22.MMEStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEContainerList(v *s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEContainerList(v *s16.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEContainerList(v *s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEContainerList(v *s16.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainerList(v *s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainerList(v *s17.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(v *s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(v *s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList].
type ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, error)
	encode  func(ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) New(value ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeModifiedItemBearerModReqIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList []ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer

func BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEContainerList(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEContainerList(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEContainerList(v *s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEContainerList(v *s17.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEContainerList(v *s17.ERABUsageReportItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABUsageReportItemIEValueCompareS1APProtocolIEContainerList(v *s17.ERABUsageReportItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *s22.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainerList(v *s18.HandoverCancelIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCancelIEValueCompareS1APProtocolIEContainerList(v *s18.HandoverCancelIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverCancelIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainerList(v *s22.HandoverFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverFailureIEValueCompareS1APProtocolIEContainerList(v *s22.HandoverFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainerList(v *s22.HandoverPreparationFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainerList(v *s22.HandoverPreparationFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainerList(v *s22.InitialContextSetupFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainerList(v *s22.InitialContextSetupFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainerList(v *s19.LocationReportingFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainerList(v *s19.LocationReportingFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEContainerList(v *s24.MDTModeExtensionIEIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEContainerList(v *s24.MDTModeExtensionIEIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(v *s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(v *s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainerList(v *s22.MMEStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainerList(v *s22.MMEStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainerList(v *s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(v *s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList].
type ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *s22.HandoverCancelAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *s22.HandoverCancelAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelIEValueCaptureS1APProtocolIESingleContainer(v *s18.HandoverCancelIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverCancelIEValueCompareS1APProtocolIESingleContainer(v *s18.HandoverCancelIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverFailureIEValueCaptureS1APProtocolIESingleContainer(v *s22.HandoverFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverFailureIEValueCompareS1APProtocolIESingleContainer(v *s22.HandoverFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIESingleContainer(v *s22.HandoverPreparationFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIESingleContainer(v *s22.HandoverPreparationFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIESingleContainer(v *s22.InitialContextSetupFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIESingleContainer(v *s22.InitialContextSetupFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s19.LocationReportingFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIESingleContainer(v *s19.LocationReportingFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIESingleContainer(v *s24.MDTModeExtensionIEIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIESingleContainer(v *s24.MDTModeExtensionIEIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *s23.MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(v *s23.MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(v *s23.MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEStatusTransferIEValueCaptureS1APProtocolIESingleContainer(v *s22.MMEStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIESingleContainer(v *s22.MMEStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEStatusTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s19.NASNonDeliveryIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(v *s19.NASNonDeliveryIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeModifiedItemBearerModReqIEFieldAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModReqIEField].
type ERABToBeModifiedItemBearerModReqIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModReqIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModReqIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModReqIEFieldAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModReqIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModReqIEContainerAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModReqIEContainer].
type ERABToBeModifiedItemBearerModReqIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModReqIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModReqIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModReqIEContainerAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModReqIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateMessageIEsValuePrivateIEFieldAPERValue is the concrete APERValue[PrivateMessageIEsValuePrivateIEField].
type PrivateMessageIEsValuePrivateIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PrivateMessageIEsValuePrivateIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PrivateMessageIEsValuePrivateIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PrivateMessageIEsValuePrivateIEFieldAPERValue) WithoutReplay() PrivateMessageIEsValuePrivateIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateMessageIEsValuePrivateIEContainerAPERValue is the concrete APERValue[PrivateMessageIEsValuePrivateIEContainer].
type PrivateMessageIEsValuePrivateIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PrivateMessageIEsValuePrivateIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PrivateMessageIEsValuePrivateIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PrivateMessageIEsValuePrivateIEContainerAPERValue) WithoutReplay() PrivateMessageIEsValuePrivateIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList].
type ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList].
type ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABReleaseListBearerRelComp(v *s16.ERABReleaseListBearerRelComp, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABReleaseListBearerRelComp(v *s16.ERABReleaseListBearerRelComp, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABSetupListBearerSURes(v *s17.ERABSetupListBearerSURes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABSetupListBearerSURes(v *s17.ERABSetupListBearerSURes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABSetupListCtxtSURes(v *s17.ERABSetupListCtxtSURes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABSetupListCtxtSURes(v *s17.ERABSetupListCtxtSURes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABToBeModifiedItemBearerModReq(v *ERABToBeModifiedItemBearerModReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s18.BridgeCaptureS1APERABLevelQoSParameters(&v.ERABLevelQoSParameters, s)
	s00.BridgeCaptureS1APNASPDU(&v.NASPDU, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeModifiedItemBearerModReq(v *ERABToBeModifiedItemBearerModReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s18.BridgeCompareS1APERABLevelQoSParameters(&v.ERABLevelQoSParameters, s)
	s02.BridgeCompareS1APNASPDU(&v.NASPDU, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeModifiedItemBearerModReqIEValue(v *ERABToBeModifiedItemBearerModReqIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(36):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeModifiedItemBearerModReq == nil)
				if v.rowERABToBeModifiedItemBearerModReq != nil {
					BridgeCaptureS1APERABToBeModifiedItemBearerModReq(v.rowERABToBeModifiedItemBearerModReq, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeModifiedItemBearerModReqIEValue) captureSemantics(s aper.SemanticCapture) ERABToBeModifiedItemBearerModReqIEValue {
	BridgeCaptureS1APERABToBeModifiedItemBearerModReqIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeModifiedItemBearerModReqIEValue(v *ERABToBeModifiedItemBearerModReqIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(36):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeModifiedItemBearerModReq == nil)
				if v.rowERABToBeModifiedItemBearerModReq != nil {
					BridgeCompareS1APERABToBeModifiedItemBearerModReq(v.rowERABToBeModifiedItemBearerModReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeModifiedItemBearerModReqIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeModifiedItemBearerModReqIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeModifiedListBearerModInd(v *s17.ERABToBeModifiedListBearerModInd, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABToBeModifiedListBearerModInd(v *s17.ERABToBeModifiedListBearerModInd, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABToBeModifiedListBearerModReq(v *ERABToBeModifiedListBearerModReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABToBeModifiedListBearerModReq(v *ERABToBeModifiedListBearerModReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABToBeSwitchedULList(v *s17.ERABToBeSwitchedULList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABToBeSwitchedULList(v *s17.ERABToBeSwitchedULList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABUsageReportList(v *s17.ERABUsageReportList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABUsageReportList(v *s17.ERABUsageReportList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APHandoverCancel(v *HandoverCancel, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverCancel(v *HandoverCancel, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverCancelAcknowledge(v *HandoverCancelAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverCancelAcknowledge(v *HandoverCancelAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverFailure(v *HandoverFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverFailure(v *HandoverFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverPreparationFailure(v *HandoverPreparationFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverPreparationFailure(v *HandoverPreparationFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APInitialContextSetupFailure(v *InitialContextSetupFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInitialContextSetupFailure(v *InitialContextSetupFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLocationReportingFailureIndication(v *LocationReportingFailureIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLocationReportingFailureIndication(v *LocationReportingFailureIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMEConfigurationUpdateAcknowledge(v *MMEConfigurationUpdateAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEConfigurationUpdateAcknowledge(v *MMEConfigurationUpdateAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMEConfigurationUpdateFailure(v *MMEConfigurationUpdateFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEConfigurationUpdateFailure(v *MMEConfigurationUpdateFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMEStatusTransfer(v *MMEStatusTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEStatusTransfer(v *MMEStatusTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNASNonDeliveryIndication(v *NASNonDeliveryIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNASNonDeliveryIndication(v *NASNonDeliveryIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPrivateMessageIEsValue(v *PrivateMessageIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s20.BridgeCaptureS1APPrivateIEID(&v.id, s)
	if v.valid {
		s.Opaque(v.opaque)
	}
	s.Bool(v.valid)
	s.End(f, nil, false)
}
func (v PrivateMessageIEsValue) captureSemantics(s aper.SemanticCapture) PrivateMessageIEsValue {
	BridgeCaptureS1APPrivateMessageIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APPrivateMessageIEsValue(v *PrivateMessageIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s20.BridgeCompareS1APPrivateIEID(&v.id, s)
	if v.valid {
		s.Opaque(v.opaque)
	}
	s.Bool(v.valid)
	s.End(f, aper.Snapshot{}, false)
}
func (v PrivateMessageIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPrivateMessageIEsValue(&v, &s)
	return s
}

// NewCauseRadioNetwork creates a Cause with the radioNetwork alternative.
func BridgeNewCauseRadioNetworkLegacy(v s00.CauseRadioNetwork) s14.Cause {
	return s14.Cause{
		Choice:       s00.CauseChoiceRadioNetwork,
		RadioNetwork: &v,
	}
}

// NewCauseTransport creates a Cause with the transport alternative.
func BridgeNewCauseTransportLegacy(v s00.CauseTransport) s14.Cause {
	return s14.Cause{
		Choice:    s00.CauseChoiceTransport,
		Transport: &v,
	}
}

// NewCauseNas creates a Cause with the nas alternative.
func BridgeNewCauseNasLegacy(v s00.CauseNas) s14.Cause {
	return s14.Cause{
		Choice: s00.CauseChoiceNas,
		Nas:    &v,
	}
}

// NewCauseProtocol creates a Cause with the protocol alternative.
func BridgeNewCauseProtocolLegacy(v s00.CauseProtocol) s14.Cause {
	return s14.Cause{
		Choice:   s00.CauseChoiceProtocol,
		Protocol: &v,
	}
}

// NewCauseMisc creates a Cause with the misc alternative.
func BridgeNewCauseMiscLegacy(v s00.CauseMisc) s14.Cause {
	return s14.Cause{
		Choice: s00.CauseChoiceMisc,
		Misc:   &v,
	}
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12 creates a DLCOUNTPDCPSNlength with the dLCOUNTValuePDCP-SNlength12 alternative.
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12Legacy(v s14.COUNTvalue) s14.DLCOUNTPDCPSNlength {
	return s14.DLCOUNTPDCPSNlength{
		Choice:                     s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12,
		DLCOUNTValuePDCPSNlength12: &v,
	}
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15 creates a DLCOUNTPDCPSNlength with the dLCOUNTValuePDCP-SNlength15 alternative.
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15Legacy(v s14.COUNTValueExtended) s14.DLCOUNTPDCPSNlength {
	return s14.DLCOUNTPDCPSNlength{
		Choice:                     s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15,
		DLCOUNTValuePDCPSNlength15: &v,
	}
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18 creates a DLCOUNTPDCPSNlength with the dLCOUNTValuePDCP-SNlength18 alternative.
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18Legacy(v s14.COUNTvaluePDCPSNlength18) s14.DLCOUNTPDCPSNlength {
	return s14.DLCOUNTPDCPSNlength{
		Choice:                     s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18,
		DLCOUNTValuePDCPSNlength18: &v,
	}
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12 creates a DLDiscarding with the discardDLCOUNTValuePDCP-SNlength12 alternative.
func BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12Legacy(v s14.COUNTvalue) s15.DLDiscarding {
	return s15.DLDiscarding{
		Choice:                            s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength12,
		DiscardDLCOUNTValuePDCPSNlength12: &v,
	}
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15 creates a DLDiscarding with the discardDLCOUNTValuePDCP-SNlength15 alternative.
func BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15Legacy(v s14.COUNTValueExtended) s15.DLDiscarding {
	return s15.DLDiscarding{
		Choice:                            s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15,
		DiscardDLCOUNTValuePDCPSNlength15: &v,
	}
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18 creates a DLDiscarding with the discardDLCOUNTValuePDCP-SNlength18 alternative.
func BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18Legacy(v s14.COUNTvaluePDCPSNlength18) s15.DLDiscarding {
	return s15.DLDiscarding{
		Choice:                            s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18,
		DiscardDLCOUNTValuePDCPSNlength18: &v,
	}
}

// NewENBIDMacroENBID creates a ENBID with the macroENB-ID alternative.
func BridgeNewENBIDMacroENBIDLegacy(v runtime.BitString) s15.ENBID {
	return s15.ENBID{
		Choice:     s00.ENBIDChoiceMacroENBID,
		MacroENBID: &v,
	}
}

// NewENBIDHomeENBID creates a ENBID with the homeENB-ID alternative.
func BridgeNewENBIDHomeENBIDLegacy(v runtime.BitString) s15.ENBID {
	return s15.ENBID{
		Choice:    s00.ENBIDChoiceHomeENBID,
		HomeENBID: &v,
	}
}

// NewENBIDShortMacroENBID creates a ENBID with the short-macroENB-ID alternative.
func BridgeNewENBIDShortMacroENBIDLegacy(v runtime.BitString) s15.ENBID {
	return s15.ENBID{
		Choice:          s00.ENBIDChoiceShortMacroENBID,
		ShortMacroENBID: &v,
	}
}

// NewENBIDLongMacroENBID creates a ENBID with the long-macroENB-ID alternative.
func BridgeNewENBIDLongMacroENBIDLegacy(v runtime.BitString) s15.ENBID {
	return s15.ENBID{
		Choice:         s00.ENBIDChoiceLongMacroENBID,
		LongMacroENBID: &v,
	}
}

// NewEventTriggerOutOfCoverage creates a EventTrigger with the outOfCoverage alternative.
func BridgeNewEventTriggerOutOfCoverageLegacy(v int64) s19.EventTrigger {
	return s19.EventTrigger{
		Choice:        s00.EventTriggerChoiceOutOfCoverage,
		OutOfCoverage: &v,
	}
}

// NewEventTriggerEventL1LoggedMDTConfig creates a EventTrigger with the eventL1LoggedMDTConfig alternative.
func BridgeNewEventTriggerEventL1LoggedMDTConfigLegacy(v s19.EventL1LoggedMDTConfig) s19.EventTrigger {
	return s19.EventTrigger{
		Choice:                 s00.EventTriggerChoiceEventL1LoggedMDTConfig,
		EventL1LoggedMDTConfig: &v,
	}
}

// NewEventTriggerChoiceExtensions creates a EventTrigger with the choice-Extensions alternative.
func BridgeNewEventTriggerChoiceExtensionsLegacy(v s09.EventTriggerExtIEValueProtocolIESingleContainer) s19.EventTrigger {
	return s19.EventTrigger{
		Choice:           s00.EventTriggerChoiceChoiceExtensions,
		ChoiceExtensions: &v,
	}
}

// NewGlobalRANNODEIDGNB creates a GlobalRANNODEID with the gNB alternative.
func BridgeNewGlobalRANNODEIDGNBLegacy(v s18.GNB) s19.GlobalRANNODEID {
	return s19.GlobalRANNODEID{
		Choice: s00.GlobalRANNODEIDChoiceGNB,
		GNB:    &v,
	}
}

// NewGlobalRANNODEIDNgENB creates a GlobalRANNODEID with the ng-eNB alternative.
func BridgeNewGlobalRANNODEIDNgENBLegacy(v s19.NGENB) s19.GlobalRANNODEID {
	return s19.GlobalRANNODEID{
		Choice: s00.GlobalRANNODEIDChoiceNgENB,
		NgENB:  &v,
	}
}

// NewGNBIdentityGNBID creates a GNBIdentity with the gNB-ID alternative.
func BridgeNewGNBIdentityGNBIDLegacy(v s00.GNBID) s18.GNBIdentity {
	return s18.GNBIdentity{
		Choice: s00.GNBIdentityChoiceGNBID,
		GNBID:  &v,
	}
}

// MarshalAPERBearersSubjectToStatusTransferListTo appends a BearersSubjectToStatusTransferList list to bb.
func BridgeMarshalAPERBearersSubjectToStatusTransferListTo(list s21.BearersSubjectToStatusTransferList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERBearersSubjectToStatusTransferListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s21.BridgeBearersSubjectToStatusTransferItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERBearersSubjectToEarlyStatusTransferListTo appends a BearersSubjectToEarlyStatusTransferList list to bb.
func BridgeMarshalAPERBearersSubjectToEarlyStatusTransferListTo(list s15.BearersSubjectToEarlyStatusTransferList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERBearersSubjectToEarlyStatusTransferListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERBearersSubjectToDLDiscardingListTo appends a BearersSubjectToDLDiscardingList list to bb.
func BridgeMarshalAPERBearersSubjectToDLDiscardingListTo(list s15.BearersSubjectToDLDiscardingList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCancelledCellinEAITo appends a CancelledCellinEAI list to bb.
func BridgeMarshalAPERCancelledCellinEAITo(list s17.CancelledCellinEAI, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCancelledCellinEAIListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCancelledCellinEAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCancelledCellinTAITo appends a CancelledCellinTAI list to bb.
func BridgeMarshalAPERCancelledCellinTAITo(list s17.CancelledCellinTAI, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCancelledCellinTAIListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCancelledCellinTAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCellIDBroadcastTo appends a CellIDBroadcast list to bb.
func BridgeMarshalAPERCellIDBroadcastTo(list s17.CellIDBroadcast, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCellIDBroadcastListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCellIDBroadcastItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCellIDCancelledTo appends a CellIDCancelled list to bb.
func BridgeMarshalAPERCellIDCancelledTo(list s17.CellIDCancelled, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCellIDCancelledListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCellIDCancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCellIdListforMDTTo appends a CellIdListforMDT list to bb.
func BridgeMarshalAPERCellIdListforMDTTo(list s17.CellIdListforMDT, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCellIdListforMDTListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCellIdListforQMCTo appends a CellIdListforQMC list to bb.
func BridgeMarshalAPERCellIdListforQMCTo(list s17.CellIdListforQMC, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCellIdListforQMCListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCNTypeRestrictionsTo appends a CNTypeRestrictions list to bb.
func BridgeMarshalAPERCNTypeRestrictionsTo(list s14.CNTypeRestrictions, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCNTypeRestrictionsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s14.BridgeCNTypeRestrictionsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCSGIdListTo appends a CSGIdList list to bb.
func BridgeMarshalAPERCSGIdListTo(list s14.CSGIdList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCSGIdListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s14.BridgeCSGIdListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCriticalityDiagnosticsIEListTo appends a CriticalityDiagnosticsIEList list to bb.
func BridgeMarshalAPERCriticalityDiagnosticsIEListTo(list s14.CriticalityDiagnosticsIEList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s14.BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERDAPSResponseInfoListTo appends a DAPSResponseInfoList list to bb.
func BridgeMarshalAPERDAPSResponseInfoListTo(list s14.DAPSResponseInfoList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERDAPSResponseInfoListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s14.BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERECGIListTo appends a ECGIList list to bb.
func BridgeMarshalAPERECGIListTo(list s17.ECGIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERECGIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPWSfailedECGIListTo appends a PWSfailedECGIList list to bb.
func BridgeMarshalAPERPWSfailedECGIListTo(list s20.PWSfailedECGIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERPWSfailedECGIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPEREmergencyAreaIDBroadcastTo appends a EmergencyAreaIDBroadcast list to bb.
func BridgeMarshalAPEREmergencyAreaIDBroadcastTo(list s22.EmergencyAreaIDBroadcast, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s22.BridgeAsn1cAPEREmergencyAreaIDBroadcastListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s22.BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPEREmergencyAreaIDCancelledTo appends a EmergencyAreaIDCancelled list to bb.
func BridgeMarshalAPEREmergencyAreaIDCancelledTo(list s22.EmergencyAreaIDCancelled, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s22.BridgeAsn1cAPEREmergencyAreaIDCancelledListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s22.BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCompletedCellinEAITo appends a CompletedCellinEAI list to bb.
func BridgeMarshalAPERCompletedCellinEAITo(list s17.CompletedCellinEAI, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCompletedCellinEAIListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCompletedCellinEAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERIEsECGIListTo appends a IEsECGIList list to bb.
func BridgeMarshalAPERIEsECGIListTo(list s18.IEsECGIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERIEsECGIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERGUMMEIListTo appends a GUMMEIList list to bb.
func BridgeMarshalAPERGUMMEIListTo(list s18.GUMMEIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERGUMMEIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeGUMMEIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABListTo appends a ERABList list to bb.
func BridgeMarshalAPERERABListTo(list s16.ERABList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeERABItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABUsageReportListTo appends a ERABUsageReportList list to bb.
func BridgeMarshalAPERERABUsageReportListTo(list s17.ERABUsageReportList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABUsageReportListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeERABUsageReportItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERForbiddenTAsTo appends a ForbiddenTAs list to bb.
func BridgeMarshalAPERForbiddenTAsTo(list s18.ForbiddenTAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERForbiddenTAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeForbiddenTAsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERForbiddenLAsTo appends a ForbiddenLAs list to bb.
func BridgeMarshalAPERForbiddenLAsTo(list s18.ForbiddenLAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERForbiddenLAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeForbiddenLAsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERInterSystemMeasurementListTo appends a InterSystemMeasurementList list to bb.
func BridgeMarshalAPERInterSystemMeasurementListTo(list s18.InterSystemMeasurementList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERInterSystemMeasurementListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeInterSystemMeasurementItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERLastVisitedPSCellListTo appends a LastVisitedPSCellList list to bb.
func BridgeMarshalAPERLastVisitedPSCellListTo(list s20.LastVisitedPSCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERLastVisitedPSCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeLastVisitedPSCellInformationMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERMBSFNResultToLogTo appends a MBSFNResultToLog list to bb.
func BridgeMarshalAPERMBSFNResultToLogTo(list s19.MBSFNResultToLog, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERMBSFNResultToLogListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeMBSFNResultToLogInfoMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPC5QoSFlowListTo appends a PC5QoSFlowList list to bb.
func BridgeMarshalAPERPC5QoSFlowListTo(list s20.PC5QoSFlowList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERPC5QoSFlowListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgePC5QoSFlowItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERRATRestrictionsTo appends a RATRestrictions list to bb.
func BridgeMarshalAPERRATRestrictionsTo(list s20.RATRestrictions, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERRATRestrictionsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeRATRestrictionsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERECGIListForRestartTo appends a ECGIListForRestart list to bb.
func BridgeMarshalAPERECGIListForRestartTo(list s17.ECGIListForRestart, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERECGIListForRestartListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCompletedCellinTAITo appends a CompletedCellinTAI list to bb.
func BridgeMarshalAPERCompletedCellinTAITo(list s17.CompletedCellinTAI, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCompletedCellinTAIListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCompletedCellinTAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERENBX2ExtTLAsTo appends a ENBX2ExtTLAs list to bb.
func BridgeMarshalAPERENBX2ExtTLAsTo(list s15.ENBX2ExtTLAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERENBX2ExtTLAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeENBX2ExtTLAMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// NewCauseRadioNetwork constructs a checked complete value.
func NewCauseRadioNetwork(v s00.CauseRadioNetwork, options ...aper.BuildOption) (s14.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseRadioNetwork")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseRadioNetwork")
	}
	value := BridgeNewCauseRadioNetworkLegacy(v)
	if _, err := s14.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseRadioNetwork")
	}
	return value, aper.OperationError(nil, "CauseRadioNetwork")
}

// NewCauseTransport constructs a checked complete value.
func NewCauseTransport(v s00.CauseTransport, options ...aper.BuildOption) (s14.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseTransport")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseTransport")
	}
	value := BridgeNewCauseTransportLegacy(v)
	if _, err := s14.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseTransport")
	}
	return value, aper.OperationError(nil, "CauseTransport")
}

// NewCauseNas constructs a checked complete value.
func NewCauseNas(v s00.CauseNas, options ...aper.BuildOption) (s14.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseNas")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseNas")
	}
	value := BridgeNewCauseNasLegacy(v)
	if _, err := s14.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseNas")
	}
	return value, aper.OperationError(nil, "CauseNas")
}

// NewCauseProtocol constructs a checked complete value.
func NewCauseProtocol(v s00.CauseProtocol, options ...aper.BuildOption) (s14.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseProtocol")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseProtocol")
	}
	value := BridgeNewCauseProtocolLegacy(v)
	if _, err := s14.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseProtocol")
	}
	return value, aper.OperationError(nil, "CauseProtocol")
}

// NewCauseMisc constructs a checked complete value.
func NewCauseMisc(v s00.CauseMisc, options ...aper.BuildOption) (s14.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseMisc")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseMisc")
	}
	value := BridgeNewCauseMiscLegacy(v)
	if _, err := s14.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseMisc")
	}
	return value, aper.OperationError(nil, "CauseMisc")
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12 constructs a checked complete value.
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12(v s14.COUNTvalue, options ...aper.BuildOption) (s14.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12Legacy(v)
	if _, err := s14.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15 constructs a checked complete value.
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15(v s14.COUNTValueExtended, options ...aper.BuildOption) (s14.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15Legacy(v)
	if _, err := s14.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18 constructs a checked complete value.
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18(v s14.COUNTvaluePDCPSNlength18, options ...aper.BuildOption) (s14.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18Legacy(v)
	if _, err := s14.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12 constructs a checked complete value.
func NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12(v s14.COUNTvalue, options ...aper.BuildOption) (s15.DLDiscarding, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength12")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength12")
	}
	value := BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12Legacy(v)
	if _, err := s15.BridgeDLDiscardingMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength12")
	}
	return value, aper.OperationError(nil, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength12")
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15 constructs a checked complete value.
func NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15(v s14.COUNTValueExtended, options ...aper.BuildOption) (s15.DLDiscarding, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength15")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength15")
	}
	value := BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15Legacy(v)
	if _, err := s15.BridgeDLDiscardingMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength15")
	}
	return value, aper.OperationError(nil, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength15")
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18 constructs a checked complete value.
func NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18(v s14.COUNTvaluePDCPSNlength18, options ...aper.BuildOption) (s15.DLDiscarding, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength18")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength18")
	}
	value := BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18Legacy(v)
	if _, err := s15.BridgeDLDiscardingMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength18")
	}
	return value, aper.OperationError(nil, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength18")
}

// NewENBIDMacroENBID constructs a checked complete value.
func NewENBIDMacroENBID(v runtime.BitString, options ...aper.BuildOption) (s15.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDMacroENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDMacroENBID")
	}
	value := BridgeNewENBIDMacroENBIDLegacy(v)
	if _, err := s15.BridgeENBIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDMacroENBID")
	}
	return value, aper.OperationError(nil, "ENBIDMacroENBID")
}

// NewENBIDHomeENBID constructs a checked complete value.
func NewENBIDHomeENBID(v runtime.BitString, options ...aper.BuildOption) (s15.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDHomeENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDHomeENBID")
	}
	value := BridgeNewENBIDHomeENBIDLegacy(v)
	if _, err := s15.BridgeENBIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDHomeENBID")
	}
	return value, aper.OperationError(nil, "ENBIDHomeENBID")
}

// NewENBIDShortMacroENBID constructs a checked complete value.
func NewENBIDShortMacroENBID(v runtime.BitString, options ...aper.BuildOption) (s15.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDShortMacroENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDShortMacroENBID")
	}
	value := BridgeNewENBIDShortMacroENBIDLegacy(v)
	if _, err := s15.BridgeENBIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDShortMacroENBID")
	}
	return value, aper.OperationError(nil, "ENBIDShortMacroENBID")
}

// NewENBIDLongMacroENBID constructs a checked complete value.
func NewENBIDLongMacroENBID(v runtime.BitString, options ...aper.BuildOption) (s15.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDLongMacroENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDLongMacroENBID")
	}
	value := BridgeNewENBIDLongMacroENBIDLegacy(v)
	if _, err := s15.BridgeENBIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDLongMacroENBID")
	}
	return value, aper.OperationError(nil, "ENBIDLongMacroENBID")
}

// NewEventTriggerOutOfCoverage constructs a checked complete value.
func NewEventTriggerOutOfCoverage(v int64, options ...aper.BuildOption) (s19.EventTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerOutOfCoverage")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerOutOfCoverage")
	}
	value := BridgeNewEventTriggerOutOfCoverageLegacy(v)
	if _, err := s19.BridgeEventTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerOutOfCoverage")
	}
	return value, aper.OperationError(nil, "EventTriggerOutOfCoverage")
}

// NewEventTriggerEventL1LoggedMDTConfig constructs a checked complete value.
func NewEventTriggerEventL1LoggedMDTConfig(v s19.EventL1LoggedMDTConfig, options ...aper.BuildOption) (s19.EventTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerEventL1LoggedMDTConfig")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerEventL1LoggedMDTConfig")
	}
	value := BridgeNewEventTriggerEventL1LoggedMDTConfigLegacy(v)
	if _, err := s19.BridgeEventTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerEventL1LoggedMDTConfig")
	}
	return value, aper.OperationError(nil, "EventTriggerEventL1LoggedMDTConfig")
}

// NewEventTriggerChoiceExtensions constructs a checked complete value.
func NewEventTriggerChoiceExtensions(v s09.EventTriggerExtIEValueProtocolIESingleContainer, options ...aper.BuildOption) (s19.EventTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerChoiceExtensions")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerChoiceExtensions")
	}
	value := BridgeNewEventTriggerChoiceExtensionsLegacy(v)
	if _, err := s19.BridgeEventTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.EventTrigger{}, aper.OperationError(err, "EventTriggerChoiceExtensions")
	}
	return value, aper.OperationError(nil, "EventTriggerChoiceExtensions")
}

// NewGlobalRANNODEIDGNB constructs a checked complete value.
func NewGlobalRANNODEIDGNB(v s18.GNB, options ...aper.BuildOption) (s19.GlobalRANNODEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDGNB")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDGNB")
	}
	value := BridgeNewGlobalRANNODEIDGNBLegacy(v)
	if _, err := s19.BridgeGlobalRANNODEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDGNB")
	}
	return value, aper.OperationError(nil, "GlobalRANNODEIDGNB")
}

// NewGlobalRANNODEIDNgENB constructs a checked complete value.
func NewGlobalRANNODEIDNgENB(v s19.NGENB, options ...aper.BuildOption) (s19.GlobalRANNODEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDNgENB")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDNgENB")
	}
	value := BridgeNewGlobalRANNODEIDNgENBLegacy(v)
	if _, err := s19.BridgeGlobalRANNODEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDNgENB")
	}
	return value, aper.OperationError(nil, "GlobalRANNODEIDNgENB")
}

// NewGNBIdentityGNBID constructs a checked complete value.
func NewGNBIdentityGNBID(v s00.GNBID, options ...aper.BuildOption) (s18.GNBIdentity, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.GNBIdentity{}, aper.OperationError(err, "GNBIdentityGNBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.GNBIdentity{}, aper.OperationError(err, "GNBIdentityGNBID")
	}
	value := BridgeNewGNBIdentityGNBIDLegacy(v)
	if _, err := s18.BridgeGNBIdentityMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.GNBIdentity{}, aper.OperationError(err, "GNBIdentityGNBID")
	}
	return value, aper.OperationError(nil, "GNBIdentityGNBID")
}

// HandoverPreparationFailure represents the ASN.1 type HandoverPreparationFailure (SEQUENCE).
type HandoverPreparationFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s22.HandoverPreparationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// HandoverFailure represents the ASN.1 type HandoverFailure (SEQUENCE).
type HandoverFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s22.HandoverFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                           `asn1:"-" json:"-"`
	extCount         int64                          `asn1:"-" json:"-"`
	extPresent       []bool                         `asn1:"-" json:"-"`
	extData          [][]byte                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// HandoverCancel represents the ASN.1 type HandoverCancel (SEQUENCE).
type HandoverCancel struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s18.HandoverCancelIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                          `asn1:"-" json:"-"`
	extCount         int64                         `asn1:"-" json:"-"`
	extPresent       []bool                        `asn1:"-" json:"-"`
	extData          [][]byte                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// HandoverCancelAcknowledge represents the ASN.1 type HandoverCancelAcknowledge (SEQUENCE).
type HandoverCancelAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s22.HandoverCancelAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                     `asn1:"-" json:"-"`
	extCount         int64                                    `asn1:"-" json:"-"`
	extPresent       []bool                                   `asn1:"-" json:"-"`
	extData          [][]byte                                 `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}
type ERABToBeModifiedListBearerModReq = []ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer

// ERABToBeModifiedItemBearerModReq represents the ASN.1 type E-RABToBeModifiedItemBearerModReq (SEQUENCE).
type ERABToBeModifiedItemBearerModReq struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	ERABID                 s00.ERABID                                           `asn1:"tag:0,context,implicit"`
	ERABLevelQoSParameters s18.ERABLevelQoSParameters                           `asn1:"tag:1,context,implicit"`
	NASPDU                 s00.NASPDU                                           `asn1:"tag:2,context,implicit"`
	IEExtensions           s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                                 `asn1:"-" json:"-"`
	extCount               int64                                                `asn1:"-" json:"-"`
	extPresent             []bool                                               `asn1:"-" json:"-"`
	extData                [][]byte                                             `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                                    `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                               `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// InitialContextSetupFailure represents the ASN.1 type InitialContextSetupFailure (SEQUENCE).
type InitialContextSetupFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s22.InitialContextSetupFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// NASNonDeliveryIndication represents the ASN.1 type NASNonDeliveryIndication (SEQUENCE).
type NASNonDeliveryIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s19.NASNonDeliveryIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MMEConfigurationUpdateAcknowledge represents the ASN.1 type MMEConfigurationUpdateAcknowledge (SEQUENCE).
type MMEConfigurationUpdateAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s22.MMEConfigurationUpdateAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                             `asn1:"-" json:"-"`
	extCount         int64                                            `asn1:"-" json:"-"`
	extPresent       []bool                                           `asn1:"-" json:"-"`
	extData          [][]byte                                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MMEConfigurationUpdateFailure represents the ASN.1 type MMEConfigurationUpdateFailure (SEQUENCE).
type MMEConfigurationUpdateFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s23.MMEConfigurationUpdateFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MMEStatusTransfer represents the ASN.1 type MMEStatusTransfer (SEQUENCE).
type MMEStatusTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s22.MMEStatusTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// LocationReportingFailureIndication represents the ASN.1 type LocationReportingFailureIndication (SEQUENCE).
type LocationReportingFailureIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s18.LocationReportingFailureIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPERERABSubjecttoDataForwardingListTo appends a ERABSubjecttoDataForwardingList list to bb.
func BridgeMarshalAPERERABSubjecttoDataForwardingListTo(list s17.ERABSubjecttoDataForwardingList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABSubjecttoDataForwardingListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeERABDataForwardingItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes HandoverPreparationFailure to APER format.
func (v *HandoverPreparationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverPreparationFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s22.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverPreparationFailure from APER format.
func (v *HandoverPreparationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverPreparationFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverPreparationFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationFailure")
	}
	bb.EnterComponent("HandoverPreparationFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverPreparationFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverPreparationFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverPreparationFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s22.HandoverPreparationFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.HandoverPreparationFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s22.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABAdmittedListTo appends a ERABAdmittedList list to bb.
func BridgeMarshalAPERERABAdmittedListTo(list s15.ERABAdmittedList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABAdmittedListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeERABAdmittedItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABFailedtoSetupListHOReqAckTo appends a ERABFailedtoSetupListHOReqAck list to bb.
func BridgeMarshalAPERERABFailedtoSetupListHOReqAckTo(list s16.ERABFailedtoSetupListHOReqAck, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABFailedtoSetupListHOReqAckListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes HandoverFailure to APER format.
func (v *HandoverFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s22.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverFailure from APER format.
func (v *HandoverFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverFailure")
	}
	bb.EnterComponent("HandoverFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s22.HandoverFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.HandoverFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s22.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABToBeSwitchedULListTo appends a ERABToBeSwitchedULList list to bb.
func BridgeMarshalAPERERABToBeSwitchedULListTo(list s17.ERABToBeSwitchedULList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABToBeSwitchedULListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeERABToBeSwitchedULItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes HandoverCancel to APER format.
func (v *HandoverCancel) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverCancel) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s18.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverCancel from APER format.
func (v *HandoverCancel) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverCancel with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverCancel) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancel")
	}
	bb.EnterComponent("HandoverCancel")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancel")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverCancel")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancel")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverCancel) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverCancel{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s18.HandoverCancelIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s18.HandoverCancelIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s18.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes HandoverCancelAcknowledge to APER format.
func (v *HandoverCancelAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverCancelAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s22.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverCancelAcknowledge from APER format.
func (v *HandoverCancelAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverCancelAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverCancelAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancelAcknowledge")
	}
	bb.EnterComponent("HandoverCancelAcknowledge")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancelAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverCancelAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancelAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverCancelAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverCancelAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s22.HandoverCancelAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.HandoverCancelAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s22.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABSetupListBearerSUResTo appends a ERABSetupListBearerSURes list to bb.
func BridgeMarshalAPERERABSetupListBearerSUResTo(list s17.ERABSetupListBearerSURes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABSetupListBearerSUResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeERABSetupItemBearerSUResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

type BridgeAsn1cAPERERABToBeModifiedListBearerModReqListValue struct {
	Value ERABToBeModifiedListBearerModReq
}

// MarshalAPERERABToBeModifiedListBearerModReqTo appends a ERABToBeModifiedListBearerModReq list to bb.
func BridgeMarshalAPERERABToBeModifiedListBearerModReqTo(list ERABToBeModifiedListBearerModReq, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERERABToBeModifiedListBearerModReqListValue{Value: list}
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

// MarshalAPER encodes ERABToBeModifiedItemBearerModReq to APER format.
func (v *ERABToBeModifiedItemBearerModReq) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABToBeModifiedItemBearerModReq) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s18.BridgeERABLevelQoSParametersMethodMarshalAPERTo(&v.ERABLevelQoSParameters, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding e-RABLevelQoSParameters: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.NASPDU), 0, 0, false); err != nil {
		return fmt.Errorf("encoding nAS-PDU: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeModifiedItemBearerModReq from APER format.
func (v *ERABToBeModifiedItemBearerModReq) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeModifiedItemBearerModReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeModifiedItemBearerModReq) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReq")
	}
	bb.EnterComponent("ERABToBeModifiedItemBearerModReq")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReq")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABToBeModifiedItemBearerModReq) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifiedItemBearerModReq{}
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
	toleranceMark_erablevelqosparameters := bb.EnterComponent("ERABLevelQoSParameters")
	if err := s18.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&v.ERABLevelQoSParameters, bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABLevelQoSParameters")
	}
	bb.LeaveComponent(toleranceMark_erablevelqosparameters)
	val_naspdu, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NASPDU")
	}
	v.NASPDU = s00.NASPDU(val_naspdu)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s21.ERABToBeModifyItemBearerModReqExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s21.ERABToBeModifyItemBearerModReqExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s21.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABModifyListBearerModResTo appends a ERABModifyListBearerModRes list to bb.
func BridgeMarshalAPERERABModifyListBearerModResTo(list s16.ERABModifyListBearerModRes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABModifyListBearerModResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeERABModifyItemBearerModResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABReleaseListBearerRelCompTo appends a ERABReleaseListBearerRelComp list to bb.
func BridgeMarshalAPERERABReleaseListBearerRelCompTo(list s16.ERABReleaseListBearerRelComp, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABReleaseListBearerRelCompListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeERABReleaseItemBearerRelCompIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABSetupListCtxtSUResTo appends a ERABSetupListCtxtSURes list to bb.
func BridgeMarshalAPERERABSetupListCtxtSUResTo(list s17.ERABSetupListCtxtSURes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABSetupListCtxtSUResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes InitialContextSetupFailure to APER format.
func (v *InitialContextSetupFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *InitialContextSetupFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s22.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes InitialContextSetupFailure from APER format.
func (v *InitialContextSetupFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InitialContextSetupFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InitialContextSetupFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupFailure")
	}
	bb.EnterComponent("InitialContextSetupFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "InitialContextSetupFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *InitialContextSetupFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitialContextSetupFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s22.InitialContextSetupFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.InitialContextSetupFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s22.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes NASNonDeliveryIndication to APER format.
func (v *NASNonDeliveryIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NASNonDeliveryIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NASNonDeliveryIndication from APER format.
func (v *NASNonDeliveryIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NASNonDeliveryIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NASNonDeliveryIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NASNonDeliveryIndication")
	}
	bb.EnterComponent("NASNonDeliveryIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NASNonDeliveryIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "NASNonDeliveryIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "NASNonDeliveryIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NASNonDeliveryIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NASNonDeliveryIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s19.NASNonDeliveryIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s19.NASNonDeliveryIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes MMEConfigurationUpdateAcknowledge to APER format.
func (v *MMEConfigurationUpdateAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMEConfigurationUpdateAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMEConfigurationUpdateAcknowledge from APER format.
func (v *MMEConfigurationUpdateAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MMEConfigurationUpdateAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MMEConfigurationUpdateAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledge")
	}
	bb.EnterComponent("MMEConfigurationUpdateAcknowledge")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MMEConfigurationUpdateAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdateAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s22.MMEConfigurationUpdateAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.MMEConfigurationUpdateAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s22.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes MMEConfigurationUpdateFailure to APER format.
func (v *MMEConfigurationUpdateFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMEConfigurationUpdateFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMEConfigurationUpdateFailure from APER format.
func (v *MMEConfigurationUpdateFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MMEConfigurationUpdateFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MMEConfigurationUpdateFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailure")
	}
	bb.EnterComponent("MMEConfigurationUpdateFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MMEConfigurationUpdateFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdateFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s23.MMEConfigurationUpdateFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.MMEConfigurationUpdateFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes MMEStatusTransfer to APER format.
func (v *MMEStatusTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMEStatusTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s22.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMEStatusTransfer from APER format.
func (v *MMEStatusTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MMEStatusTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MMEStatusTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEStatusTransfer")
	}
	bb.EnterComponent("MMEStatusTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEStatusTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEStatusTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEStatusTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MMEStatusTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEStatusTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s22.MMEStatusTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.MMEStatusTransferIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s22.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes LocationReportingFailureIndication to APER format.
func (v *LocationReportingFailureIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LocationReportingFailureIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s18.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LocationReportingFailureIndication from APER format.
func (v *LocationReportingFailureIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LocationReportingFailureIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LocationReportingFailureIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingFailureIndication")
	}
	bb.EnterComponent("LocationReportingFailureIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingFailureIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "LocationReportingFailureIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingFailureIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LocationReportingFailureIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LocationReportingFailureIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s18.LocationReportingFailureIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s18.LocationReportingFailureIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s18.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABToBeModifiedListBearerModIndTo appends a ERABToBeModifiedListBearerModInd list to bb.
func BridgeMarshalAPERERABToBeModifiedListBearerModIndTo(list s17.ERABToBeModifiedListBearerModInd, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABToBeModifiedListBearerModIndListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABNotToBeModifiedListBearerModIndTo appends a ERABNotToBeModifiedListBearerModInd list to bb.
func BridgeMarshalAPERERABNotToBeModifiedListBearerModIndTo(list s16.ERABNotToBeModifiedListBearerModInd, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABNotToBeModifiedListBearerModIndListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABModifyListBearerModConfTo appends a ERABModifyListBearerModConf list to bb.
func BridgeMarshalAPERERABModifyListBearerModConfTo(list s16.ERABModifyListBearerModConf, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABModifyListBearerModConfListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeERABModifyItemBearerModConfIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABFailedToResumeListResumeReqTo appends a ERABFailedToResumeListResumeReq list to bb.
func BridgeMarshalAPERERABFailedToResumeListResumeReqTo(list s16.ERABFailedToResumeListResumeReq, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABFailedToResumeListResumeReqListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeERABFailedToResumeItemResumeReqIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERERABFailedToResumeListResumeResTo appends a ERABFailedToResumeListResumeRes list to bb.
func BridgeMarshalAPERERABFailedToResumeListResumeResTo(list s16.ERABFailedToResumeListResumeRes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERERABFailedToResumeListResumeResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeERABFailedToResumeItemResumeResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func (v *ERABToBeModifiedItemBearerModReq) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeModifiedItemBearerModReq", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeModifiedItemBearerModReq", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeModifiedItemBearerModReq) WithoutReplay() ERABToBeModifiedItemBearerModReq {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeModifiedItemBearerModReq
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverCancel) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverCancel", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverCancel", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverCancel) WithoutReplay() HandoverCancel {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverCancel
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverCancelAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverCancelAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverCancelAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverCancelAcknowledge) WithoutReplay() HandoverCancelAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverCancelAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverFailure) WithoutReplay() HandoverFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverPreparationFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverPreparationFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverPreparationFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverPreparationFailure) WithoutReplay() HandoverPreparationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverPreparationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InitialContextSetupFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "InitialContextSetupFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InitialContextSetupFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InitialContextSetupFailure) WithoutReplay() InitialContextSetupFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InitialContextSetupFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LocationReportingFailureIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LocationReportingFailureIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LocationReportingFailureIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LocationReportingFailureIndication) WithoutReplay() LocationReportingFailureIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LocationReportingFailureIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEConfigurationUpdateAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEConfigurationUpdateAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEConfigurationUpdateAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEConfigurationUpdateAcknowledge) WithoutReplay() MMEConfigurationUpdateAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEConfigurationUpdateAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEConfigurationUpdateFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEConfigurationUpdateFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEConfigurationUpdateFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEConfigurationUpdateFailure) WithoutReplay() MMEConfigurationUpdateFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEConfigurationUpdateFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEStatusTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEStatusTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEStatusTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEStatusTransfer) WithoutReplay() MMEStatusTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEStatusTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NASNonDeliveryIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NASNonDeliveryIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NASNonDeliveryIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NASNonDeliveryIndication) WithoutReplay() NASNonDeliveryIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NASNonDeliveryIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABToBeModifiedItemBearerModReq) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABToBeModifiedItemBearerModReq) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeModifiedItemBearerModReq.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeModifiedItemBearerModReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABToBeModifiedItemBearerModReq) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeModifiedItemBearerModReq.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeModifiedItemBearerModReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverCancel) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverCancel) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverCancel.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverCancel.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverCancel) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverCancel.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverCancel.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverCancelAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverCancelAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverCancelAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverCancelAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverCancelAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverCancelAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverCancelAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverPreparationFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverPreparationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverPreparationFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverPreparationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverPreparationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverPreparationFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverPreparationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *InitialContextSetupFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *InitialContextSetupFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InitialContextSetupFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InitialContextSetupFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *InitialContextSetupFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InitialContextSetupFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InitialContextSetupFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *LocationReportingFailureIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LocationReportingFailureIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LocationReportingFailureIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LocationReportingFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LocationReportingFailureIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LocationReportingFailureIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LocationReportingFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MMEConfigurationUpdateAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMEConfigurationUpdateAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMEConfigurationUpdateAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MMEConfigurationUpdateFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMEConfigurationUpdateFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMEConfigurationUpdateFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MMEStatusTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMEStatusTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMEStatusTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NASNonDeliveryIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NASNonDeliveryIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NASNonDeliveryIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NASNonDeliveryIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NASNonDeliveryIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NASNonDeliveryIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NASNonDeliveryIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeModifiedItemBearerModReq) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeModifiedItemBearerModReq")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeModifiedItemBearerModReq) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeModifiedItemBearerModReq")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeModifiedItemBearerModReq(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeModifiedItemBearerModReq")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeModifiedItemBearerModReq")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeModifiedItemBearerModReq) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeModifiedItemBearerModReq")
}
func (v *ERABToBeModifiedItemBearerModReq) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeModifiedItemBearerModReq")
}
func (v *ERABToBeModifiedItemBearerModReq) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeModifiedItemBearerModReq(v, &s)
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
func (v *ERABToBeModifiedItemBearerModReq) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeModifiedItemBearerModReq) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *HandoverCancel) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverCancel")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverCancel) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverCancel")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverCancel(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverCancel")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverCancel")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverCancel) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverCancel")
}
func (v *HandoverCancel) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverCancel")
}
func (v *HandoverCancel) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverCancel(v, &s)
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
func (v *HandoverCancel) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverCancel) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *HandoverCancelAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverCancelAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverCancelAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverCancelAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverCancelAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverCancelAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverCancelAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverCancelAcknowledge")
}
func (v *HandoverCancelAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverCancelAcknowledge")
}
func (v *HandoverCancelAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverCancelAcknowledge(v, &s)
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
func (v *HandoverCancelAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverCancelAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *HandoverFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverFailure")
}
func (v *HandoverFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverFailure")
}
func (v *HandoverFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverFailure(v, &s)
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
func (v *HandoverFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *HandoverPreparationFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverPreparationFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverPreparationFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverPreparationFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverPreparationFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverPreparationFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverPreparationFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverPreparationFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverPreparationFailure")
}
func (v *HandoverPreparationFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverPreparationFailure")
}
func (v *HandoverPreparationFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverPreparationFailure(v, &s)
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
func (v *HandoverPreparationFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverPreparationFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *InitialContextSetupFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InitialContextSetupFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InitialContextSetupFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InitialContextSetupFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInitialContextSetupFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InitialContextSetupFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InitialContextSetupFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InitialContextSetupFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InitialContextSetupFailure")
}
func (v *InitialContextSetupFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InitialContextSetupFailure")
}
func (v *InitialContextSetupFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInitialContextSetupFailure(v, &s)
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
func (v *InitialContextSetupFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InitialContextSetupFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LocationReportingFailureIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LocationReportingFailureIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LocationReportingFailureIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLocationReportingFailureIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LocationReportingFailureIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LocationReportingFailureIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LocationReportingFailureIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LocationReportingFailureIndication")
}
func (v *LocationReportingFailureIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LocationReportingFailureIndication")
}
func (v *LocationReportingFailureIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLocationReportingFailureIndication(v, &s)
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
func (v *LocationReportingFailureIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LocationReportingFailureIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MMEConfigurationUpdateAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEConfigurationUpdateAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEConfigurationUpdateAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEConfigurationUpdateAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEConfigurationUpdateAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEConfigurationUpdateAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
}
func (v *MMEConfigurationUpdateAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
}
func (v *MMEConfigurationUpdateAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEConfigurationUpdateAcknowledge(v, &s)
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
func (v *MMEConfigurationUpdateAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEConfigurationUpdateAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MMEConfigurationUpdateFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEConfigurationUpdateFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEConfigurationUpdateFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEConfigurationUpdateFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEConfigurationUpdateFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEConfigurationUpdateFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEConfigurationUpdateFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEConfigurationUpdateFailure")
}
func (v *MMEConfigurationUpdateFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEConfigurationUpdateFailure")
}
func (v *MMEConfigurationUpdateFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEConfigurationUpdateFailure(v, &s)
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
func (v *MMEConfigurationUpdateFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEConfigurationUpdateFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MMEStatusTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEStatusTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEStatusTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEStatusTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEStatusTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEStatusTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEStatusTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEStatusTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEStatusTransfer")
}
func (v *MMEStatusTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEStatusTransfer")
}
func (v *MMEStatusTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEStatusTransfer(v, &s)
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
func (v *MMEStatusTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEStatusTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NASNonDeliveryIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NASNonDeliveryIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NASNonDeliveryIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNASNonDeliveryIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NASNonDeliveryIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NASNonDeliveryIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NASNonDeliveryIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NASNonDeliveryIndication")
}
func (v *NASNonDeliveryIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NASNonDeliveryIndication")
}
func (v *NASNonDeliveryIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNASNonDeliveryIndication(v, &s)
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
func (v *NASNonDeliveryIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NASNonDeliveryIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeModifiedItemBearerModReq) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeModifiedItemBearerModReq")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeModifiedItemBearerModReq
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeModifiedItemBearerModReq(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeModifiedItemBearerModReq{}
		return report, aper.OperationError(err, "ERABToBeModifiedItemBearerModReq")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeModifiedItemBearerModReq")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverCancel) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverCancel")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverCancel
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverCancel(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverCancel{}
		return report, aper.OperationError(err, "HandoverCancel")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverCancel")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverCancelAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverCancelAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverCancelAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverCancelAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverCancelAcknowledge{}
		return report, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverCancelAcknowledge")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverFailure{}
		return report, aper.OperationError(err, "HandoverFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverPreparationFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverPreparationFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverPreparationFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverPreparationFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverPreparationFailure{}
		return report, aper.OperationError(err, "HandoverPreparationFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverPreparationFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *InitialContextSetupFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InitialContextSetupFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InitialContextSetupFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInitialContextSetupFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InitialContextSetupFailure{}
		return report, aper.OperationError(err, "InitialContextSetupFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InitialContextSetupFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LocationReportingFailureIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LocationReportingFailureIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LocationReportingFailureIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLocationReportingFailureIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LocationReportingFailureIndication{}
		return report, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LocationReportingFailureIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEConfigurationUpdateAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEConfigurationUpdateAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEConfigurationUpdateAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEConfigurationUpdateAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEConfigurationUpdateAcknowledge{}
		return report, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEConfigurationUpdateAcknowledge")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEConfigurationUpdateFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEConfigurationUpdateFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEConfigurationUpdateFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEConfigurationUpdateFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEConfigurationUpdateFailure{}
		return report, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEConfigurationUpdateFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEStatusTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEStatusTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEStatusTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEStatusTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEStatusTransfer{}
		return report, aper.OperationError(err, "MMEStatusTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEStatusTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NASNonDeliveryIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NASNonDeliveryIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NASNonDeliveryIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNASNonDeliveryIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NASNonDeliveryIndication{}
		return report, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NASNonDeliveryIndication")
}

// NewCellLoadReportingResponseEUTRAN creates a CellLoadReportingResponse with the eUTRAN alternative.
func BridgeNewCellLoadReportingResponseEUTRANLegacy(v s17.EUTRANcellLoadReportingResponse) s17.CellLoadReportingResponse {
	return s17.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceEUTRAN,
		EUTRAN: &v,
	}
}

// NewCellLoadReportingResponseUTRAN creates a CellLoadReportingResponse with the uTRAN alternative.
func BridgeNewCellLoadReportingResponseUTRANLegacy(v []byte) s17.CellLoadReportingResponse {
	return s17.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceUTRAN,
		UTRAN:  v,
	}
}

// NewCellLoadReportingResponseGERAN creates a CellLoadReportingResponse with the gERAN alternative.
func BridgeNewCellLoadReportingResponseGERANLegacy(v []byte) s17.CellLoadReportingResponse {
	return s17.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceGERAN,
		GERAN:  v,
	}
}

// NewCellLoadReportingResponseEHRPD creates a CellLoadReportingResponse with the eHRPD alternative.
func BridgeNewCellLoadReportingResponseEHRPDLegacy(v s15.EHRPDSectorLoadReportingResponse) s17.CellLoadReportingResponse {
	return s17.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceEHRPD,
		EHRPD:  &v,
	}
}

// NewIRATCellIDEUTRAN creates a IRATCellID with the eUTRAN alternative.
func BridgeNewIRATCellIDEUTRANLegacy(v []byte) s18.IRATCellID {
	return s18.IRATCellID{
		Choice: s00.IRATCellIDChoiceEUTRAN,
		EUTRAN: v,
	}
}

// NewIRATCellIDGERAN creates a IRATCellID with the gERAN alternative.
func BridgeNewIRATCellIDGERANLegacy(v []byte) s18.IRATCellID {
	return s18.IRATCellID{
		Choice: s00.IRATCellIDChoiceGERAN,
		GERAN:  v,
	}
}

// NewIRATCellIDEHRPD creates a IRATCellID with the eHRPD alternative.
func BridgeNewIRATCellIDEHRPDLegacy(v s00.EHRPDSectorID) s18.IRATCellID {
	return s18.IRATCellID{
		Choice: s00.IRATCellIDChoiceEHRPD,
		EHRPD:  &v,
	}
}

// NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN creates a FailureEventReport with the tooEarlyInterRATHOReportFromEUTRAN alternative.
func BridgeNewFailureEventReportTooEarlyInterRATHOReportFromEUTRANLegacy(v s20.TooEarlyInterRATHOReportReportFromEUTRAN) s20.FailureEventReport {
	return s20.FailureEventReport{
		Choice:                             s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN,
		TooEarlyInterRATHOReportFromEUTRAN: &v,
	}
}

// MarshalAPERRequestedCellListTo appends a RequestedCellList list to bb.
func BridgeMarshalAPERRequestedCellListTo(list s20.RequestedCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERRequestedCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeIRATCellIDMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERReportingCellListTo appends a ReportingCellList list to bb.
func BridgeMarshalAPERReportingCellListTo(list s20.ReportingCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERReportingCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeReportingCellListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERMultiCellLoadReportingResponseTo appends a MultiCellLoadReportingResponse list to bb.
func BridgeMarshalAPERMultiCellLoadReportingResponseTo(list s19.MultiCellLoadReportingResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERMultiCellLoadReportingResponseListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCandidateCellListTo appends a CandidateCellList list to bb.
func BridgeMarshalAPERCandidateCellListTo(list s18.CandidateCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCandidateCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeIRATCellIDMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCandidatePCIListTo appends a CandidatePCIList list to bb.
func BridgeMarshalAPERCandidatePCIListTo(list s14.CandidatePCIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCandidatePCIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s14.BridgeCandidatePCIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCellsToActivateListTo appends a CellsToActivateList list to bb.
func BridgeMarshalAPERCellsToActivateListTo(list s14.CellsToActivateList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERCellsToActivateListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s14.BridgeCellsToActivateListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERActivatedCellsListTo appends a ActivatedCellsList list to bb.
func BridgeMarshalAPERActivatedCellsListTo(list s14.ActivatedCellsList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERActivatedCellsListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s14.BridgeActivatedCellsListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERNotificationCellListTo appends a NotificationCellList list to bb.
func BridgeMarshalAPERNotificationCellListTo(list s20.NotificationCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s21.BridgeAsn1cAPERNotificationCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeNotificationCellListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// NewCellLoadReportingResponseEUTRAN constructs a checked complete value.
func NewCellLoadReportingResponseEUTRAN(v s17.EUTRANcellLoadReportingResponse, options ...aper.BuildOption) (s17.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	value := BridgeNewCellLoadReportingResponseEUTRANLegacy(v)
	if _, err := s17.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseEUTRAN")
}

// NewCellLoadReportingResponseUTRAN constructs a checked complete value.
func NewCellLoadReportingResponseUTRAN(v []byte, options ...aper.BuildOption) (s17.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	value := BridgeNewCellLoadReportingResponseUTRANLegacy(v)
	if _, err := s17.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseUTRAN")
}

// NewCellLoadReportingResponseGERAN constructs a checked complete value.
func NewCellLoadReportingResponseGERAN(v []byte, options ...aper.BuildOption) (s17.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	value := BridgeNewCellLoadReportingResponseGERANLegacy(v)
	if _, err := s17.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseGERAN")
}

// NewCellLoadReportingResponseEHRPD constructs a checked complete value.
func NewCellLoadReportingResponseEHRPD(v s15.EHRPDSectorLoadReportingResponse, options ...aper.BuildOption) (s17.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
	}
	value := BridgeNewCellLoadReportingResponseEHRPDLegacy(v)
	if _, err := s17.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseEHRPD")
}

// NewIRATCellIDEUTRAN constructs a checked complete value.
func NewIRATCellIDEUTRAN(v []byte, options ...aper.BuildOption) (s18.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDEUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDEUTRAN")
	}
	value := BridgeNewIRATCellIDEUTRANLegacy(v)
	if _, err := s18.BridgeIRATCellIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDEUTRAN")
	}
	return value, aper.OperationError(nil, "IRATCellIDEUTRAN")
}

// NewIRATCellIDEHRPD constructs a checked complete value.
func NewIRATCellIDEHRPD(v s00.EHRPDSectorID, options ...aper.BuildOption) (s18.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDEHRPD")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDEHRPD")
	}
	value := BridgeNewIRATCellIDEHRPDLegacy(v)
	if _, err := s18.BridgeIRATCellIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDEHRPD")
	}
	return value, aper.OperationError(nil, "IRATCellIDEHRPD")
}

// NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN constructs a checked complete value.
func NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN(v s20.TooEarlyInterRATHOReportReportFromEUTRAN, options ...aper.BuildOption) (s20.FailureEventReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
	}
	value := BridgeNewFailureEventReportTooEarlyInterRATHOReportFromEUTRANLegacy(v)
	if _, err := s20.BridgeFailureEventReportMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
	}
	return value, aper.OperationError(nil, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
}

type ERABToBeModifiedItemBearerModReqIEValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowERABToBeModifiedItemBearerModReq *ERABToBeModifiedItemBearerModReq
}

func (v ERABToBeModifiedItemBearerModReqIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(36):
		return v.rowERABToBeModifiedItemBearerModReq != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeModifiedItemBearerModReqIEValue and reports whether the opaque alternative is selected.
func (v *ERABToBeModifiedItemBearerModReqIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeModifiedItemBearerModReqIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModReqIEs"}}
}
func (ERABToBeModifiedItemBearerModReqIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(36):
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

// AsERABToBeModifiedItemBearerModReq returns the selected ERABToBeModifiedItemBearerModReq value of ERABToBeModifiedItemBearerModReqIEValue and reports whether that alternative is active.
func (v *ERABToBeModifiedItemBearerModReqIEValue) AsERABToBeModifiedItemBearerModReq() (*ERABToBeModifiedItemBearerModReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(36) || v.rowERABToBeModifiedItemBearerModReq == nil {
		return nil, false
	}
	return v.rowERABToBeModifiedItemBearerModReq, true
}
func (v ERABToBeModifiedItemBearerModReqIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeModifiedItemBearerModReqIEValue, error) {
	out := ERABToBeModifiedItemBearerModReqIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(36):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABToBeModifiedItemBearerModReq
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeModifiedItemBearerModReq:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABToBeModifiedItemBearerModReq")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABToBeModifiedItemBearerModReq = &value
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
func (v ERABToBeModifiedItemBearerModReqIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeModifiedItemBearerModReqIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(36):
		if v.rowERABToBeModifiedItemBearerModReq == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeModifiedItemBearerModReqIEs.id-E-RABToBeModifiedItemBearerModReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABToBeModifiedItemBearerModReq.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeModifiedItemBearerModReqIEValue:", v.id)
	}
}
func BridgeEqualPrivateID(a, b s20.PrivateIEID, budget *aper.DecodeBudget) bool {
	if a.Choice != b.Choice {
		return false
	}
	switch a.Choice {
	case s00.PrivateIEIDChoiceLocal:
		return a.Local != nil && b.Local != nil && *a.Local == *b.Local
	case s00.PrivateIEIDChoiceGlobal:
		if a.Global == nil || b.Global == nil {
			return false
		}
		if budget != nil {
			if err := aper.NewBudgetBuffer(budget).ChargeWork(uint64(len(a.Global.Encoded()))); err != nil {
				return false
			}
		}
		if budget != nil {
			if err := aper.NewBudgetBuffer(budget).ChargeWork(uint64(len(b.Global.Encoded()))); err != nil {
				return false
			}
		}
		return *a.Global == *b.Global
	}
	return false
}

type PrivateMessageIEsValue struct {
	id     s20.PrivateIEID
	opaque aper.OpaqueOpenType
	valid  bool
}

// TS 36.413 V19.2.0 §9.3.7: compare the semantic private ID without replay padding.
func (v PrivateMessageIEsValue) matchesID(id s20.PrivateIEID, budgets ...*aper.DecodeBudget) bool {
	var budget *aper.DecodeBudget
	for _, candidate := range budgets {
		budget = candidate
		break
	}
	return v.valid && BridgeEqualPrivateID(v.id, id, budget)
}
func (PrivateMessageIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PrivateMessageIEs"}}
}
func (PrivateMessageIEsValue) decode(id s20.PrivateIEID, raw aper.OpaqueOpenType) (PrivateMessageIEsValue, error) {
	if err := raw.Observe(aper.UnknownIE); err != nil {
		return PrivateMessageIEsValue{}, err
	}
	owned, err := s21.BridgeClonePrivateID(id, raw.BudgetBuffer().Budget())
	if err != nil {
		return PrivateMessageIEsValue{}, err
	}
	return PrivateMessageIEsValue{id: owned, opaque: raw.Detached(), valid: true}, nil
}
func (v PrivateMessageIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v PrivateMessageIEsValue) encodeFresh(_ bool, budget *aper.DecodeBudget) ([]byte, error) {
	if !v.valid {
		return nil, fmt.Errorf("%s missing opaque value", "PrivateMessageIEs:")
	}
	return aper.CopyOpaque(v.opaque, budget)
}

// Opaque returns the retained opaque open value of PrivateMessageIEsValue and reports whether the opaque alternative is selected.
func (v *PrivateMessageIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.valid {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}

type PrivateMessageIETable struct{}

func PrivateMessageIEs() PrivateMessageIETable { return PrivateMessageIETable{} }

// ID returns the ASN.1 object-set identity of PrivateMessageIETable.
func (PrivateMessageIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PrivateMessageIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PrivateMessageIETable.
func (PrivateMessageIETable) Table() s00.PrivateMessageIEsValuePrivateTable {
	return func() s00.PrivateMessageIEsValuePrivateTable {
		sealed := s00.PrivateMessageIEsValuePrivateTable{}
		*s00.BridgePrivateMessageIEsValuePrivateTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PrivateMessageIETable.
func (PrivateMessageIETable) NewOpaque(id s20.PrivateIEID, criticality s00.Criticality, data []byte) (PrivateMessageIEsValuePrivateIEField, error) {
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	if criticality < 0 || criticality > 2 {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(fmt.Errorf("invalid private IE criticality %d", criticality), "Opaque")
	}
	if _, err := s20.BridgePrivateIEIDMethodMarshalAPERBudget(&id, budget, true); err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	owned, err := s21.BridgeClonePrivateID(id, budget)
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	opaque, err := aper.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	field := PrivateMessageIEsValuePrivateIEField{Id: id, Criticality: criticality, Value: PrivateMessageIEsValue{id: owned, opaque: opaque, valid: true}}
	bb := aper.NewBudgetBuffer(budget)
	if err := field.marshalAPERTo(bb); err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	return field, aper.OperationError(nil, "Opaque")
}

type ERABToBeModifiedItemBearerModReqIETable struct{}

func ERABToBeModifiedItemBearerModReqIEs() ERABToBeModifiedItemBearerModReqIETable {
	return ERABToBeModifiedItemBearerModReqIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeModifiedItemBearerModReqIETable.
func (ERABToBeModifiedItemBearerModReqIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModReqIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeModifiedItemBearerModReqIETable.
func (ERABToBeModifiedItemBearerModReqIETable) Table() s00.ERABToBeModifiedItemBearerModReqIEValueIETable {
	return func() s00.ERABToBeModifiedItemBearerModReqIEValueIETable {
		sealed := s00.ERABToBeModifiedItemBearerModReqIEValueIETable{}
		*s00.BridgeERABToBeModifiedItemBearerModReqIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeModifiedItemBearerModReqIETable) infoERABToBeModifiedItemBearerModReq() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABToBeModifiedItemBearerModReqIEs().ID(), ID: s00.ProtocolIEID(36), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModReqIEs", Row: "id-E-RABToBeModifiedItemBearerModReq"}}}
}

// ERABToBeModifiedItemBearerModReq returns the typed binding for the ERABToBeModifiedItemBearerModReq row of ERABToBeModifiedItemBearerModReqIETable.
func (t ERABToBeModifiedItemBearerModReqIETable) ERABToBeModifiedItemBearerModReq() ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding {
	return ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding{info: t.infoERABToBeModifiedItemBearerModReq(), codec: ERABToBeModifiedItemBearerModReqValueCodec{path: "ERABToBeModifiedItemBearerModReq",
		decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReq, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABToBeModifiedItemBearerModReq
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeModifiedItemBearerModReq")
			var zero ERABToBeModifiedItemBearerModReqIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(36), raw)
			if err != nil {
				var empty ERABToBeModifiedItemBearerModReq
				return empty, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReq")
			}
			value, ok := decoded.AsERABToBeModifiedItemBearerModReq()
			if !ok {
				var empty ERABToBeModifiedItemBearerModReq
				return empty, fmt.Errorf("binding E-RABToBeModifiedItemBearerModReqIEs.id-E-RABToBeModifiedItemBearerModReq: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABToBeModifiedItemBearerModReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeModifiedItemBearerModReqIEValue{id: s00.ProtocolIEID(36), rowERABToBeModifiedItemBearerModReq: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABToBeModifiedItemBearerModReq, options aper.DecodeState) (ERABToBeModifiedItemBearerModReq, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABToBeModifiedItemBearerModReq(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeModifiedItemBearerModReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABToBeModifiedItemBearerModReq(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeModifiedItemBearerModReq"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABToBeModifiedItemBearerModReq) ERABToBeModifiedItemBearerModReqIEValue {
		return ERABToBeModifiedItemBearerModReqIEValue{id: s00.ProtocolIEID(36), rowERABToBeModifiedItemBearerModReq: &value}
	}, get: func(value *ERABToBeModifiedItemBearerModReqIEValue) (*ERABToBeModifiedItemBearerModReq, bool) {
		return value.AsERABToBeModifiedItemBearerModReq()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeModifiedItemBearerModReqIETable.
func (t ERABToBeModifiedItemBearerModReqIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABToBeModifiedItemBearerModReqIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeModifiedItemBearerModReqIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(36):
		return ERABToBeModifiedItemBearerModReqIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeModifiedItemBearerModReq requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeModifiedItemBearerModReqIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeModifiedItemBearerModReqIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeModifiedItemBearerModReqIEField{Id: id, Criticality: criticality, Value: ERABToBeModifiedItemBearerModReqIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ERABToBeModifiedItemBearerModReqCodec binds the complete APER value type.
func ERABToBeModifiedItemBearerModReqCodec() ERABToBeModifiedItemBearerModReqValueCodec {
	return ERABToBeModifiedItemBearerModReqIEs().ERABToBeModifiedItemBearerModReq().Codec()
}
func BridgeMergeNestedValidation(dst *s21.ValidationReport, src s21.ValidationReport) {
	if *s21.BridgeValidationReportFieldErr(dst) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(&src) != nil {
		*s21.BridgeValidationReportFieldErr(dst) = *s21.BridgeValidationReportFieldErr(&src)
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(dst))
	var err error
	dst.Issues, err = aper.AppendValues(bb, dst.Issues, src.Issues...)
	if err != nil {
		*s21.BridgeValidationReportFieldErr(dst) = err
		return
	}
	dst.Deferred, err = aper.AppendValues(bb, dst.Deferred, src.Deferred...)
	if err != nil {
		*s21.BridgeValidationReportFieldErr(dst) = err
		return
	}
	dst.Unchecked, err = aper.AppendValues(bb, dst.Unchecked, src.Unchecked...)
	if err != nil {
		*s21.BridgeValidationReportFieldErr(dst) = err
		return
	}
	if !src.Complete {
		dst.Complete = false
	}
}
func BridgeERABToBeModifiedItemBearerModReqAPERValueFieldContext(v *ERABToBeModifiedItemBearerModReqAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqAPERValueFieldReceived(v *ERABToBeModifiedItemBearerModReqAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqAPERValueFieldReplay(v *ERABToBeModifiedItemBearerModReqAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqAPERValueFieldWithoutReplay(v *ERABToBeModifiedItemBearerModReqAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBindingFieldCodec(v *ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding) *ERABToBeModifiedItemBearerModReqValueCodec {
	return &v.codec
}
func BridgeERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBindingFieldGet(v *ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding) *func(*ERABToBeModifiedItemBearerModReqIEValue) (*ERABToBeModifiedItemBearerModReq, bool) {
	return &v.get
}
func BridgeERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBindingFieldInfo(v *ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBindingFieldInject(v *ERABToBeModifiedItemBearerModReqERABToBeModifiedItemBearerModReqIEBinding) *func(ERABToBeModifiedItemBearerModReq) ERABToBeModifiedItemBearerModReqIEValue {
	return &v.inject
}
func BridgeERABToBeModifiedItemBearerModReqFieldExtCount(v *ERABToBeModifiedItemBearerModReq) *int64 {
	return &v.extCount
}
func BridgeERABToBeModifiedItemBearerModReqFieldExtData(v *ERABToBeModifiedItemBearerModReq) *[][]byte {
	return &v.extData
}
func BridgeERABToBeModifiedItemBearerModReqFieldExtOrigin(v *ERABToBeModifiedItemBearerModReq) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABToBeModifiedItemBearerModReqFieldExtPresent(v *ERABToBeModifiedItemBearerModReq) *[]bool {
	return &v.extPresent
}
func BridgeERABToBeModifiedItemBearerModReqFieldExtWire(v *ERABToBeModifiedItemBearerModReq) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABToBeModifiedItemBearerModReqFieldIEExtensionsIndef(v *ERABToBeModifiedItemBearerModReq) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABToBeModifiedItemBearerModReqFieldPerExtPadding(v *ERABToBeModifiedItemBearerModReq) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABToBeModifiedItemBearerModReqFieldPerPadding(v *ERABToBeModifiedItemBearerModReq) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABToBeModifiedItemBearerModReqFieldReceived(v *ERABToBeModifiedItemBearerModReq) *bool {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqFieldReceivedAbsolute(v *ERABToBeModifiedItemBearerModReq) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeModifiedItemBearerModReqFieldReceivedBytes(v *ERABToBeModifiedItemBearerModReq) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeModifiedItemBearerModReqFieldReceivedLocation(v *ERABToBeModifiedItemBearerModReq) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeModifiedItemBearerModReqFieldReplay(v *ERABToBeModifiedItemBearerModReq) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqFieldStream(v *ERABToBeModifiedItemBearerModReq) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeModifiedItemBearerModReqFieldWithoutReplay(v *ERABToBeModifiedItemBearerModReq) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerAPERValueFieldContext(v *ERABToBeModifiedItemBearerModReqIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerAPERValueFieldReceived(v *ERABToBeModifiedItemBearerModReqIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerAPERValueFieldReplay(v *ERABToBeModifiedItemBearerModReqIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerAPERValueFieldWithoutReplay(v *ERABToBeModifiedItemBearerModReqIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModReqIEContainerValueCodec) *func(ERABToBeModifiedItemBearerModReqIEContainer, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModReqIEContainerValueCodec) *func(ERABToBeModifiedItemBearerModReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerValueCodecFieldContext(v *ERABToBeModifiedItemBearerModReqIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModReqIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEContainer, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModReqIEContainerValueCodec) *func(ERABToBeModifiedItemBearerModReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerValueCodecFieldPath(v *ERABToBeModifiedItemBearerModReqIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerValueCodecMethodEncodeBudgetValue(v ERABToBeModifiedItemBearerModReqIEContainerValueCodec, a0 ERABToBeModifiedItemBearerModReqIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqIEContainerValueCodecMethodEncodeChanged(v ERABToBeModifiedItemBearerModReqIEContainerValueCodec, a0 ERABToBeModifiedItemBearerModReqIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldAPERValueFieldContext(v *ERABToBeModifiedItemBearerModReqIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldAPERValueFieldReceived(v *ERABToBeModifiedItemBearerModReqIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldAPERValueFieldReplay(v *ERABToBeModifiedItemBearerModReqIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldAPERValueFieldWithoutReplay(v *ERABToBeModifiedItemBearerModReqIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldFieldReceived(v *ERABToBeModifiedItemBearerModReqIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldFieldReplay(v *ERABToBeModifiedItemBearerModReqIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldFieldStream(v *ERABToBeModifiedItemBearerModReqIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldFieldWithoutReplay(v *ERABToBeModifiedItemBearerModReqIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldMethodMarshalAPERTo(v *ERABToBeModifiedItemBearerModReqIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldMethodUnmarshalAPERFrom(v *ERABToBeModifiedItemBearerModReqIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModReqIEFieldValueCodec) *func(ERABToBeModifiedItemBearerModReqIEField, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModReqIEFieldValueCodec) *func(ERABToBeModifiedItemBearerModReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldValueCodecFieldContext(v *ERABToBeModifiedItemBearerModReqIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModReqIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEField, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModReqIEFieldValueCodec) *func(ERABToBeModifiedItemBearerModReqIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldValueCodecFieldPath(v *ERABToBeModifiedItemBearerModReqIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldValueCodecMethodEncodeBudgetValue(v ERABToBeModifiedItemBearerModReqIEFieldValueCodec, a0 ERABToBeModifiedItemBearerModReqIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldValueCodecMethodEncodeChanged(v ERABToBeModifiedItemBearerModReqIEFieldValueCodec, a0 ERABToBeModifiedItemBearerModReqIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifiedItemBearerModReqIETableMethodInfoERABToBeModifiedItemBearerModReq(v ERABToBeModifiedItemBearerModReqIETable) s00.FieldInfo {
	return v.infoERABToBeModifiedItemBearerModReq()
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValueFieldContext(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValueFieldReceived(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValueFieldReplay(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodecFieldContext(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodecFieldPath(v *ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec, a0 ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec, a0 ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueFieldId(v *ERABToBeModifiedItemBearerModReqIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeModifiedItemBearerModReqIEValueFieldIsOpaque(v *ERABToBeModifiedItemBearerModReqIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeModifiedItemBearerModReqIEValueFieldOpaque(v *ERABToBeModifiedItemBearerModReqIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeModifiedItemBearerModReqIEValueFieldReceived(v *ERABToBeModifiedItemBearerModReqIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqIEValueFieldReplay(v *ERABToBeModifiedItemBearerModReqIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqIEValueFieldRowERABToBeModifiedItemBearerModReq(v *ERABToBeModifiedItemBearerModReqIEValue) **ERABToBeModifiedItemBearerModReq {
	return &v.rowERABToBeModifiedItemBearerModReq
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodCaptureSemantics(v ERABToBeModifiedItemBearerModReqIEValue, a0 aper.SemanticCapture) ERABToBeModifiedItemBearerModReqIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodCompareSemantics(v ERABToBeModifiedItemBearerModReqIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodDecode(v ERABToBeModifiedItemBearerModReqIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeModifiedItemBearerModReqIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodEncode(v ERABToBeModifiedItemBearerModReqIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodEncodeFresh(v ERABToBeModifiedItemBearerModReqIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodMatchesID(v ERABToBeModifiedItemBearerModReqIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodReason(v ERABToBeModifiedItemBearerModReqIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodRule(v ERABToBeModifiedItemBearerModReqIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec, a0 ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec, a0 ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifiedItemBearerModReqMethodMarshalAPERBudget(v *ERABToBeModifiedItemBearerModReq, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeModifiedItemBearerModReqMethodMarshalAPERBudgetValue(v *ERABToBeModifiedItemBearerModReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeModifiedItemBearerModReqMethodMarshalAPERChanged(v *ERABToBeModifiedItemBearerModReq, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqMethodMarshalAPERChangedValue(v *ERABToBeModifiedItemBearerModReq, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqMethodMarshalAPERLegacy(v *ERABToBeModifiedItemBearerModReq) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeModifiedItemBearerModReqMethodMarshalAPERNewValue(v *ERABToBeModifiedItemBearerModReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeModifiedItemBearerModReqMethodMarshalAPERPlanned(v *ERABToBeModifiedItemBearerModReq, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqMethodMarshalAPERTo(v *ERABToBeModifiedItemBearerModReq, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeModifiedItemBearerModReqMethodUnmarshalAPERFrom(v *ERABToBeModifiedItemBearerModReq, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeModifiedItemBearerModReqMethodUnmarshalAPERLegacy(v *ERABToBeModifiedItemBearerModReq, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeModifiedItemBearerModReqMethodUnmarshalAPERWithOptions(v *ERABToBeModifiedItemBearerModReq, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeModifiedItemBearerModReqValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModReqValueCodec) *func(ERABToBeModifiedItemBearerModReq, aper.DecodeState) (ERABToBeModifiedItemBearerModReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModReqValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModReqValueCodec) *func(ERABToBeModifiedItemBearerModReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModReqValueCodecFieldContext(v *ERABToBeModifiedItemBearerModReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModReqValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModReqValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModReq, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModReqValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModReqValueCodec) *func(ERABToBeModifiedItemBearerModReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModReqValueCodecFieldPath(v *ERABToBeModifiedItemBearerModReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModReqValueCodecMethodEncodeBudgetValue(v ERABToBeModifiedItemBearerModReqValueCodec, a0 ERABToBeModifiedItemBearerModReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifiedItemBearerModReqValueCodecMethodEncodeChanged(v ERABToBeModifiedItemBearerModReqValueCodec, a0 ERABToBeModifiedItemBearerModReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifiedListBearerModReqAPERValueFieldContext(v *ERABToBeModifiedListBearerModReqAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedListBearerModReqAPERValueFieldReceived(v *ERABToBeModifiedListBearerModReqAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifiedListBearerModReqAPERValueFieldReplay(v *ERABToBeModifiedListBearerModReqAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedListBearerModReqAPERValueFieldWithoutReplay(v *ERABToBeModifiedListBearerModReqAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedListBearerModReqValueCodecFieldCapture(v *ERABToBeModifiedListBearerModReqValueCodec) *func(ERABToBeModifiedListBearerModReq, aper.DecodeState) (ERABToBeModifiedListBearerModReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedListBearerModReqValueCodecFieldCompare(v *ERABToBeModifiedListBearerModReqValueCodec) *func(ERABToBeModifiedListBearerModReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedListBearerModReqValueCodecFieldContext(v *ERABToBeModifiedListBearerModReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedListBearerModReqValueCodecFieldDecode(v *ERABToBeModifiedListBearerModReqValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedListBearerModReq, error) {
	return &v.decode
}
func BridgeERABToBeModifiedListBearerModReqValueCodecFieldEncode(v *ERABToBeModifiedListBearerModReqValueCodec) *func(ERABToBeModifiedListBearerModReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedListBearerModReqValueCodecFieldPath(v *ERABToBeModifiedListBearerModReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedListBearerModReqValueCodecMethodEncodeBudgetValue(v ERABToBeModifiedListBearerModReqValueCodec, a0 ERABToBeModifiedListBearerModReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifiedListBearerModReqValueCodecMethodEncodeChanged(v ERABToBeModifiedListBearerModReqValueCodec, a0 ERABToBeModifiedListBearerModReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelAPERValueFieldContext(v *HandoverCancelAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAPERValueFieldReceived(v *HandoverCancelAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelAPERValueFieldReplay(v *HandoverCancelAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAPERValueFieldWithoutReplay(v *HandoverCancelAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeAPERValueFieldContext(v *HandoverCancelAcknowledgeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeAPERValueFieldReceived(v *HandoverCancelAcknowledgeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeAPERValueFieldReplay(v *HandoverCancelAcknowledgeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeAPERValueFieldWithoutReplay(v *HandoverCancelAcknowledgeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeFieldExtCount(v *HandoverCancelAcknowledge) *int64 {
	return &v.extCount
}
func BridgeHandoverCancelAcknowledgeFieldExtData(v *HandoverCancelAcknowledge) *[][]byte {
	return &v.extData
}
func BridgeHandoverCancelAcknowledgeFieldExtOrigin(v *HandoverCancelAcknowledge) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverCancelAcknowledgeFieldExtPresent(v *HandoverCancelAcknowledge) *[]bool {
	return &v.extPresent
}
func BridgeHandoverCancelAcknowledgeFieldExtWire(v *HandoverCancelAcknowledge) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeHandoverCancelAcknowledgeFieldPerExtPadding(v *HandoverCancelAcknowledge) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverCancelAcknowledgeFieldPerPadding(v *HandoverCancelAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverCancelAcknowledgeFieldProtocolIEsIndef(v *HandoverCancelAcknowledge) *bool {
	return &v.protocolIEsIndef
}
func BridgeHandoverCancelAcknowledgeFieldReceived(v *HandoverCancelAcknowledge) *bool {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeFieldReceivedAbsolute(v *HandoverCancelAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgeHandoverCancelAcknowledgeFieldReceivedBytes(v *HandoverCancelAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverCancelAcknowledgeFieldReceivedLocation(v *HandoverCancelAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverCancelAcknowledgeFieldReplay(v *HandoverCancelAcknowledge) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeFieldStream(v *HandoverCancelAcknowledge) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverCancelAcknowledgeFieldWithoutReplay(v *HandoverCancelAcknowledge) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(v *HandoverCancelAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudgetValue(v *HandoverCancelAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERChanged(v *HandoverCancelAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERChangedValue(v *HandoverCancelAcknowledge, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERLegacy(v *HandoverCancelAcknowledge) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERNewValue(v *HandoverCancelAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERPlanned(v *HandoverCancelAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERTo(v *HandoverCancelAcknowledge, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverCancelAcknowledgeMethodUnmarshalAPERFrom(v *HandoverCancelAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverCancelAcknowledgeMethodUnmarshalAPERLegacy(v *HandoverCancelAcknowledge, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverCancelAcknowledgeMethodUnmarshalAPERWithOptions(v *HandoverCancelAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverCancelAcknowledgeValueCodecFieldCapture(v *HandoverCancelAcknowledgeValueCodec) *func(HandoverCancelAcknowledge, aper.DecodeState) (HandoverCancelAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelAcknowledgeValueCodecFieldCompare(v *HandoverCancelAcknowledgeValueCodec) *func(HandoverCancelAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelAcknowledgeValueCodecFieldContext(v *HandoverCancelAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeValueCodecFieldDecode(v *HandoverCancelAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelAcknowledge, error) {
	return &v.decode
}
func BridgeHandoverCancelAcknowledgeValueCodecFieldEncode(v *HandoverCancelAcknowledgeValueCodec) *func(HandoverCancelAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelAcknowledgeValueCodecFieldPath(v *HandoverCancelAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelAcknowledgeValueCodecMethodEncodeBudgetValue(v HandoverCancelAcknowledgeValueCodec, a0 HandoverCancelAcknowledge, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeValueCodecMethodEncodeChanged(v HandoverCancelAcknowledgeValueCodec, a0 HandoverCancelAcknowledge, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelFieldExtCount(v *HandoverCancel) *int64                { return &v.extCount }
func BridgeHandoverCancelFieldExtData(v *HandoverCancel) *[][]byte              { return &v.extData }
func BridgeHandoverCancelFieldExtOrigin(v *HandoverCancel) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeHandoverCancelFieldExtPresent(v *HandoverCancel) *[]bool             { return &v.extPresent }
func BridgeHandoverCancelFieldExtWire(v *HandoverCancel) *[]aper.WireSpan       { return &v.extWire }
func BridgeHandoverCancelFieldPerExtPadding(v *HandoverCancel) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverCancelFieldPerPadding(v *HandoverCancel) *aper.FinalPadding { return &v.perPadding }
func BridgeHandoverCancelFieldProtocolIEsIndef(v *HandoverCancel) *bool        { return &v.protocolIEsIndef }
func BridgeHandoverCancelFieldReceived(v *HandoverCancel) *bool                { return &v.received }
func BridgeHandoverCancelFieldReceivedAbsolute(v *HandoverCancel) *bool        { return &v.receivedAbsolute }
func BridgeHandoverCancelFieldReceivedBytes(v *HandoverCancel) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverCancelFieldReceivedLocation(v *HandoverCancel) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverCancelFieldReplay(v *HandoverCancel) *aper.Snapshot { return &v.replay }
func BridgeHandoverCancelFieldStream(v *HandoverCancel) *aper.WireSpan { return &v.stream }
func BridgeHandoverCancelFieldWithoutReplay(v *HandoverCancel) *bool   { return &v.withoutReplay }
func BridgeHandoverCancelMethodMarshalAPERBudget(v *HandoverCancel, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverCancelMethodMarshalAPERBudgetValue(v *HandoverCancel, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverCancelMethodMarshalAPERChanged(v *HandoverCancel, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverCancelMethodMarshalAPERChangedValue(v *HandoverCancel, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverCancelMethodMarshalAPERLegacy(v *HandoverCancel) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverCancelMethodMarshalAPERNewValue(v *HandoverCancel, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverCancelMethodMarshalAPERPlanned(v *HandoverCancel, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverCancelMethodMarshalAPERTo(v *HandoverCancel, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverCancelMethodUnmarshalAPERFrom(v *HandoverCancel, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverCancelMethodUnmarshalAPERLegacy(v *HandoverCancel, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverCancelMethodUnmarshalAPERWithOptions(v *HandoverCancel, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverCancelValueCodecFieldCapture(v *HandoverCancelValueCodec) *func(HandoverCancel, aper.DecodeState) (HandoverCancel, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelValueCodecFieldCompare(v *HandoverCancelValueCodec) *func(HandoverCancel, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelValueCodecFieldContext(v *HandoverCancelValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelValueCodecFieldDecode(v *HandoverCancelValueCodec) *func([]byte, aper.DecodeState) (HandoverCancel, error) {
	return &v.decode
}
func BridgeHandoverCancelValueCodecFieldEncode(v *HandoverCancelValueCodec) *func(HandoverCancel, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelValueCodecFieldPath(v *HandoverCancelValueCodec) *aper.Path { return &v.path }
func BridgeHandoverCancelValueCodecMethodEncodeBudgetValue(v HandoverCancelValueCodec, a0 HandoverCancel, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelValueCodecMethodEncodeChanged(v HandoverCancelValueCodec, a0 HandoverCancel, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverFailureAPERValueFieldContext(v *HandoverFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureAPERValueFieldReceived(v *HandoverFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverFailureAPERValueFieldReplay(v *HandoverFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverFailureAPERValueFieldWithoutReplay(v *HandoverFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverFailureFieldExtCount(v *HandoverFailure) *int64   { return &v.extCount }
func BridgeHandoverFailureFieldExtData(v *HandoverFailure) *[][]byte { return &v.extData }
func BridgeHandoverFailureFieldExtOrigin(v *HandoverFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverFailureFieldExtPresent(v *HandoverFailure) *[]bool       { return &v.extPresent }
func BridgeHandoverFailureFieldExtWire(v *HandoverFailure) *[]aper.WireSpan { return &v.extWire }
func BridgeHandoverFailureFieldPerExtPadding(v *HandoverFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverFailureFieldPerPadding(v *HandoverFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverFailureFieldProtocolIEsIndef(v *HandoverFailure) *bool { return &v.protocolIEsIndef }
func BridgeHandoverFailureFieldReceived(v *HandoverFailure) *bool         { return &v.received }
func BridgeHandoverFailureFieldReceivedAbsolute(v *HandoverFailure) *bool { return &v.receivedAbsolute }
func BridgeHandoverFailureFieldReceivedBytes(v *HandoverFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverFailureFieldReceivedLocation(v *HandoverFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverFailureFieldReplay(v *HandoverFailure) *aper.Snapshot { return &v.replay }
func BridgeHandoverFailureFieldStream(v *HandoverFailure) *aper.WireSpan { return &v.stream }
func BridgeHandoverFailureFieldWithoutReplay(v *HandoverFailure) *bool   { return &v.withoutReplay }
func BridgeHandoverFailureMethodMarshalAPERBudget(v *HandoverFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverFailureMethodMarshalAPERBudgetValue(v *HandoverFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverFailureMethodMarshalAPERChanged(v *HandoverFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverFailureMethodMarshalAPERChangedValue(v *HandoverFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverFailureMethodMarshalAPERLegacy(v *HandoverFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverFailureMethodMarshalAPERNewValue(v *HandoverFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverFailureMethodMarshalAPERPlanned(v *HandoverFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverFailureMethodMarshalAPERTo(v *HandoverFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverFailureMethodUnmarshalAPERFrom(v *HandoverFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverFailureMethodUnmarshalAPERLegacy(v *HandoverFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverFailureMethodUnmarshalAPERWithOptions(v *HandoverFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverFailureValueCodecFieldCapture(v *HandoverFailureValueCodec) *func(HandoverFailure, aper.DecodeState) (HandoverFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFailureValueCodecFieldCompare(v *HandoverFailureValueCodec) *func(HandoverFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFailureValueCodecFieldContext(v *HandoverFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureValueCodecFieldDecode(v *HandoverFailureValueCodec) *func([]byte, aper.DecodeState) (HandoverFailure, error) {
	return &v.decode
}
func BridgeHandoverFailureValueCodecFieldEncode(v *HandoverFailureValueCodec) *func(HandoverFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFailureValueCodecFieldPath(v *HandoverFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverFailureValueCodecMethodEncodeBudgetValue(v HandoverFailureValueCodec, a0 HandoverFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverFailureValueCodecMethodEncodeChanged(v HandoverFailureValueCodec, a0 HandoverFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverPreparationFailureAPERValueFieldContext(v *HandoverPreparationFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureAPERValueFieldReceived(v *HandoverPreparationFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverPreparationFailureAPERValueFieldReplay(v *HandoverPreparationFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureAPERValueFieldWithoutReplay(v *HandoverPreparationFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverPreparationFailureFieldExtCount(v *HandoverPreparationFailure) *int64 {
	return &v.extCount
}
func BridgeHandoverPreparationFailureFieldExtData(v *HandoverPreparationFailure) *[][]byte {
	return &v.extData
}
func BridgeHandoverPreparationFailureFieldExtOrigin(v *HandoverPreparationFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverPreparationFailureFieldExtPresent(v *HandoverPreparationFailure) *[]bool {
	return &v.extPresent
}
func BridgeHandoverPreparationFailureFieldExtWire(v *HandoverPreparationFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeHandoverPreparationFailureFieldPerExtPadding(v *HandoverPreparationFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverPreparationFailureFieldPerPadding(v *HandoverPreparationFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverPreparationFailureFieldProtocolIEsIndef(v *HandoverPreparationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeHandoverPreparationFailureFieldReceived(v *HandoverPreparationFailure) *bool {
	return &v.received
}
func BridgeHandoverPreparationFailureFieldReceivedAbsolute(v *HandoverPreparationFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeHandoverPreparationFailureFieldReceivedBytes(v *HandoverPreparationFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverPreparationFailureFieldReceivedLocation(v *HandoverPreparationFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverPreparationFailureFieldReplay(v *HandoverPreparationFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureFieldStream(v *HandoverPreparationFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverPreparationFailureFieldWithoutReplay(v *HandoverPreparationFailure) *bool {
	return &v.withoutReplay
}
func BridgeHandoverPreparationFailureMethodMarshalAPERBudget(v *HandoverPreparationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverPreparationFailureMethodMarshalAPERBudgetValue(v *HandoverPreparationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverPreparationFailureMethodMarshalAPERChanged(v *HandoverPreparationFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverPreparationFailureMethodMarshalAPERChangedValue(v *HandoverPreparationFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverPreparationFailureMethodMarshalAPERLegacy(v *HandoverPreparationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverPreparationFailureMethodMarshalAPERNewValue(v *HandoverPreparationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverPreparationFailureMethodMarshalAPERPlanned(v *HandoverPreparationFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverPreparationFailureMethodMarshalAPERTo(v *HandoverPreparationFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverPreparationFailureMethodUnmarshalAPERFrom(v *HandoverPreparationFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverPreparationFailureMethodUnmarshalAPERLegacy(v *HandoverPreparationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverPreparationFailureMethodUnmarshalAPERWithOptions(v *HandoverPreparationFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverPreparationFailureValueCodecFieldCapture(v *HandoverPreparationFailureValueCodec) *func(HandoverPreparationFailure, aper.DecodeState) (HandoverPreparationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverPreparationFailureValueCodecFieldCompare(v *HandoverPreparationFailureValueCodec) *func(HandoverPreparationFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverPreparationFailureValueCodecFieldContext(v *HandoverPreparationFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureValueCodecFieldDecode(v *HandoverPreparationFailureValueCodec) *func([]byte, aper.DecodeState) (HandoverPreparationFailure, error) {
	return &v.decode
}
func BridgeHandoverPreparationFailureValueCodecFieldEncode(v *HandoverPreparationFailureValueCodec) *func(HandoverPreparationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverPreparationFailureValueCodecFieldPath(v *HandoverPreparationFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverPreparationFailureValueCodecMethodEncodeBudgetValue(v HandoverPreparationFailureValueCodec, a0 HandoverPreparationFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverPreparationFailureValueCodecMethodEncodeChanged(v HandoverPreparationFailureValueCodec, a0 HandoverPreparationFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupFailureAPERValueFieldContext(v *InitialContextSetupFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureAPERValueFieldReceived(v *InitialContextSetupFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupFailureAPERValueFieldReplay(v *InitialContextSetupFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureAPERValueFieldWithoutReplay(v *InitialContextSetupFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupFailureFieldExtCount(v *InitialContextSetupFailure) *int64 {
	return &v.extCount
}
func BridgeInitialContextSetupFailureFieldExtData(v *InitialContextSetupFailure) *[][]byte {
	return &v.extData
}
func BridgeInitialContextSetupFailureFieldExtOrigin(v *InitialContextSetupFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeInitialContextSetupFailureFieldExtPresent(v *InitialContextSetupFailure) *[]bool {
	return &v.extPresent
}
func BridgeInitialContextSetupFailureFieldExtWire(v *InitialContextSetupFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeInitialContextSetupFailureFieldPerExtPadding(v *InitialContextSetupFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeInitialContextSetupFailureFieldPerPadding(v *InitialContextSetupFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeInitialContextSetupFailureFieldProtocolIEsIndef(v *InitialContextSetupFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeInitialContextSetupFailureFieldReceived(v *InitialContextSetupFailure) *bool {
	return &v.received
}
func BridgeInitialContextSetupFailureFieldReceivedAbsolute(v *InitialContextSetupFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeInitialContextSetupFailureFieldReceivedBytes(v *InitialContextSetupFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInitialContextSetupFailureFieldReceivedLocation(v *InitialContextSetupFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeInitialContextSetupFailureFieldReplay(v *InitialContextSetupFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureFieldStream(v *InitialContextSetupFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeInitialContextSetupFailureFieldWithoutReplay(v *InitialContextSetupFailure) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupFailureMethodMarshalAPERBudget(v *InitialContextSetupFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInitialContextSetupFailureMethodMarshalAPERBudgetValue(v *InitialContextSetupFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeInitialContextSetupFailureMethodMarshalAPERChanged(v *InitialContextSetupFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInitialContextSetupFailureMethodMarshalAPERChangedValue(v *InitialContextSetupFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInitialContextSetupFailureMethodMarshalAPERLegacy(v *InitialContextSetupFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInitialContextSetupFailureMethodMarshalAPERNewValue(v *InitialContextSetupFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeInitialContextSetupFailureMethodMarshalAPERPlanned(v *InitialContextSetupFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeInitialContextSetupFailureMethodMarshalAPERTo(v *InitialContextSetupFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitialContextSetupFailureMethodUnmarshalAPERFrom(v *InitialContextSetupFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitialContextSetupFailureMethodUnmarshalAPERLegacy(v *InitialContextSetupFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInitialContextSetupFailureMethodUnmarshalAPERWithOptions(v *InitialContextSetupFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInitialContextSetupFailureValueCodecFieldCapture(v *InitialContextSetupFailureValueCodec) *func(InitialContextSetupFailure, aper.DecodeState) (InitialContextSetupFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupFailureValueCodecFieldCompare(v *InitialContextSetupFailureValueCodec) *func(InitialContextSetupFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupFailureValueCodecFieldContext(v *InitialContextSetupFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureValueCodecFieldDecode(v *InitialContextSetupFailureValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupFailure, error) {
	return &v.decode
}
func BridgeInitialContextSetupFailureValueCodecFieldEncode(v *InitialContextSetupFailureValueCodec) *func(InitialContextSetupFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupFailureValueCodecFieldPath(v *InitialContextSetupFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupFailureValueCodecMethodEncodeBudgetValue(v InitialContextSetupFailureValueCodec, a0 InitialContextSetupFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupFailureValueCodecMethodEncodeChanged(v InitialContextSetupFailureValueCodec, a0 InitialContextSetupFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingFailureIndicationAPERValueFieldContext(v *LocationReportingFailureIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationAPERValueFieldReceived(v *LocationReportingFailureIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingFailureIndicationAPERValueFieldReplay(v *LocationReportingFailureIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationAPERValueFieldWithoutReplay(v *LocationReportingFailureIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingFailureIndicationFieldExtCount(v *LocationReportingFailureIndication) *int64 {
	return &v.extCount
}
func BridgeLocationReportingFailureIndicationFieldExtData(v *LocationReportingFailureIndication) *[][]byte {
	return &v.extData
}
func BridgeLocationReportingFailureIndicationFieldExtOrigin(v *LocationReportingFailureIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeLocationReportingFailureIndicationFieldExtPresent(v *LocationReportingFailureIndication) *[]bool {
	return &v.extPresent
}
func BridgeLocationReportingFailureIndicationFieldExtWire(v *LocationReportingFailureIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeLocationReportingFailureIndicationFieldPerExtPadding(v *LocationReportingFailureIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeLocationReportingFailureIndicationFieldPerPadding(v *LocationReportingFailureIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeLocationReportingFailureIndicationFieldProtocolIEsIndef(v *LocationReportingFailureIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeLocationReportingFailureIndicationFieldReceived(v *LocationReportingFailureIndication) *bool {
	return &v.received
}
func BridgeLocationReportingFailureIndicationFieldReceivedAbsolute(v *LocationReportingFailureIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeLocationReportingFailureIndicationFieldReceivedBytes(v *LocationReportingFailureIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLocationReportingFailureIndicationFieldReceivedLocation(v *LocationReportingFailureIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeLocationReportingFailureIndicationFieldReplay(v *LocationReportingFailureIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationFieldStream(v *LocationReportingFailureIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeLocationReportingFailureIndicationFieldWithoutReplay(v *LocationReportingFailureIndication) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingFailureIndicationMethodMarshalAPERBudget(v *LocationReportingFailureIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLocationReportingFailureIndicationMethodMarshalAPERBudgetValue(v *LocationReportingFailureIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLocationReportingFailureIndicationMethodMarshalAPERChanged(v *LocationReportingFailureIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLocationReportingFailureIndicationMethodMarshalAPERChangedValue(v *LocationReportingFailureIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLocationReportingFailureIndicationMethodMarshalAPERLegacy(v *LocationReportingFailureIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLocationReportingFailureIndicationMethodMarshalAPERNewValue(v *LocationReportingFailureIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLocationReportingFailureIndicationMethodMarshalAPERPlanned(v *LocationReportingFailureIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLocationReportingFailureIndicationMethodMarshalAPERTo(v *LocationReportingFailureIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLocationReportingFailureIndicationMethodUnmarshalAPERFrom(v *LocationReportingFailureIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLocationReportingFailureIndicationMethodUnmarshalAPERLegacy(v *LocationReportingFailureIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLocationReportingFailureIndicationMethodUnmarshalAPERWithOptions(v *LocationReportingFailureIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLocationReportingFailureIndicationValueCodecFieldCapture(v *LocationReportingFailureIndicationValueCodec) *func(LocationReportingFailureIndication, aper.DecodeState) (LocationReportingFailureIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingFailureIndicationValueCodecFieldCompare(v *LocationReportingFailureIndicationValueCodec) *func(LocationReportingFailureIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingFailureIndicationValueCodecFieldContext(v *LocationReportingFailureIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationValueCodecFieldDecode(v *LocationReportingFailureIndicationValueCodec) *func([]byte, aper.DecodeState) (LocationReportingFailureIndication, error) {
	return &v.decode
}
func BridgeLocationReportingFailureIndicationValueCodecFieldEncode(v *LocationReportingFailureIndicationValueCodec) *func(LocationReportingFailureIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingFailureIndicationValueCodecFieldPath(v *LocationReportingFailureIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingFailureIndicationValueCodecMethodEncodeBudgetValue(v LocationReportingFailureIndicationValueCodec, a0 LocationReportingFailureIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingFailureIndicationValueCodecMethodEncodeChanged(v LocationReportingFailureIndicationValueCodec, a0 LocationReportingFailureIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateAcknowledgeAPERValueFieldContext(v *MMEConfigurationUpdateAcknowledgeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeAPERValueFieldReceived(v *MMEConfigurationUpdateAcknowledgeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeAPERValueFieldReplay(v *MMEConfigurationUpdateAcknowledgeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateAcknowledgeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldExtCount(v *MMEConfigurationUpdateAcknowledge) *int64 {
	return &v.extCount
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldExtData(v *MMEConfigurationUpdateAcknowledge) *[][]byte {
	return &v.extData
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldExtOrigin(v *MMEConfigurationUpdateAcknowledge) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldExtPresent(v *MMEConfigurationUpdateAcknowledge) *[]bool {
	return &v.extPresent
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldExtWire(v *MMEConfigurationUpdateAcknowledge) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldPerExtPadding(v *MMEConfigurationUpdateAcknowledge) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldPerPadding(v *MMEConfigurationUpdateAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldProtocolIEsIndef(v *MMEConfigurationUpdateAcknowledge) *bool {
	return &v.protocolIEsIndef
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldReceived(v *MMEConfigurationUpdateAcknowledge) *bool {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedAbsolute(v *MMEConfigurationUpdateAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedBytes(v *MMEConfigurationUpdateAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedLocation(v *MMEConfigurationUpdateAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldReplay(v *MMEConfigurationUpdateAcknowledge) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldStream(v *MMEConfigurationUpdateAcknowledge) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEConfigurationUpdateAcknowledgeFieldWithoutReplay(v *MMEConfigurationUpdateAcknowledge) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v *MMEConfigurationUpdateAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudgetValue(v *MMEConfigurationUpdateAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERChanged(v *MMEConfigurationUpdateAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERChangedValue(v *MMEConfigurationUpdateAcknowledge, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERLegacy(v *MMEConfigurationUpdateAcknowledge) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERNewValue(v *MMEConfigurationUpdateAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERPlanned(v *MMEConfigurationUpdateAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERTo(v *MMEConfigurationUpdateAcknowledge, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodUnmarshalAPERFrom(v *MMEConfigurationUpdateAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodUnmarshalAPERLegacy(v *MMEConfigurationUpdateAcknowledge, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodUnmarshalAPERWithOptions(v *MMEConfigurationUpdateAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldCapture(v *MMEConfigurationUpdateAcknowledgeValueCodec) *func(MMEConfigurationUpdateAcknowledge, aper.DecodeState) (MMEConfigurationUpdateAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldCompare(v *MMEConfigurationUpdateAcknowledgeValueCodec) *func(MMEConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldContext(v *MMEConfigurationUpdateAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldDecode(v *MMEConfigurationUpdateAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledge, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldEncode(v *MMEConfigurationUpdateAcknowledgeValueCodec) *func(MMEConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldPath(v *MMEConfigurationUpdateAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateAcknowledgeValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateAcknowledgeValueCodec, a0 MMEConfigurationUpdateAcknowledge, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeValueCodecMethodEncodeChanged(v MMEConfigurationUpdateAcknowledgeValueCodec, a0 MMEConfigurationUpdateAcknowledge, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateFailureAPERValueFieldContext(v *MMEConfigurationUpdateFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureAPERValueFieldReceived(v *MMEConfigurationUpdateFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureAPERValueFieldReplay(v *MMEConfigurationUpdateFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFailureFieldExtCount(v *MMEConfigurationUpdateFailure) *int64 {
	return &v.extCount
}
func BridgeMMEConfigurationUpdateFailureFieldExtData(v *MMEConfigurationUpdateFailure) *[][]byte {
	return &v.extData
}
func BridgeMMEConfigurationUpdateFailureFieldExtOrigin(v *MMEConfigurationUpdateFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMMEConfigurationUpdateFailureFieldExtPresent(v *MMEConfigurationUpdateFailure) *[]bool {
	return &v.extPresent
}
func BridgeMMEConfigurationUpdateFailureFieldExtWire(v *MMEConfigurationUpdateFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMMEConfigurationUpdateFailureFieldPerExtPadding(v *MMEConfigurationUpdateFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMMEConfigurationUpdateFailureFieldPerPadding(v *MMEConfigurationUpdateFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMMEConfigurationUpdateFailureFieldProtocolIEsIndef(v *MMEConfigurationUpdateFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeMMEConfigurationUpdateFailureFieldReceived(v *MMEConfigurationUpdateFailure) *bool {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureFieldReceivedAbsolute(v *MMEConfigurationUpdateFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeMMEConfigurationUpdateFailureFieldReceivedBytes(v *MMEConfigurationUpdateFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEConfigurationUpdateFailureFieldReceivedLocation(v *MMEConfigurationUpdateFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMEConfigurationUpdateFailureFieldReplay(v *MMEConfigurationUpdateFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureFieldStream(v *MMEConfigurationUpdateFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEConfigurationUpdateFailureFieldWithoutReplay(v *MMEConfigurationUpdateFailure) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(v *MMEConfigurationUpdateFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudgetValue(v *MMEConfigurationUpdateFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERChanged(v *MMEConfigurationUpdateFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERChangedValue(v *MMEConfigurationUpdateFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERLegacy(v *MMEConfigurationUpdateFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERNewValue(v *MMEConfigurationUpdateFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERPlanned(v *MMEConfigurationUpdateFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERTo(v *MMEConfigurationUpdateFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEConfigurationUpdateFailureMethodUnmarshalAPERFrom(v *MMEConfigurationUpdateFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEConfigurationUpdateFailureMethodUnmarshalAPERLegacy(v *MMEConfigurationUpdateFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMEConfigurationUpdateFailureMethodUnmarshalAPERWithOptions(v *MMEConfigurationUpdateFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMEConfigurationUpdateFailureValueCodecFieldCapture(v *MMEConfigurationUpdateFailureValueCodec) *func(MMEConfigurationUpdateFailure, aper.DecodeState) (MMEConfigurationUpdateFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureValueCodecFieldCompare(v *MMEConfigurationUpdateFailureValueCodec) *func(MMEConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureValueCodecFieldContext(v *MMEConfigurationUpdateFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureValueCodecFieldDecode(v *MMEConfigurationUpdateFailureValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailure, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureValueCodecFieldEncode(v *MMEConfigurationUpdateFailureValueCodec) *func(MMEConfigurationUpdateFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureValueCodecFieldPath(v *MMEConfigurationUpdateFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateFailureValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateFailureValueCodec, a0 MMEConfigurationUpdateFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureValueCodecMethodEncodeChanged(v MMEConfigurationUpdateFailureValueCodec, a0 MMEConfigurationUpdateFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEStatusTransferAPERValueFieldContext(v *MMEStatusTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferAPERValueFieldReceived(v *MMEStatusTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEStatusTransferAPERValueFieldReplay(v *MMEStatusTransferAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEStatusTransferAPERValueFieldWithoutReplay(v *MMEStatusTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEStatusTransferFieldExtCount(v *MMEStatusTransfer) *int64   { return &v.extCount }
func BridgeMMEStatusTransferFieldExtData(v *MMEStatusTransfer) *[][]byte { return &v.extData }
func BridgeMMEStatusTransferFieldExtOrigin(v *MMEStatusTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMMEStatusTransferFieldExtPresent(v *MMEStatusTransfer) *[]bool       { return &v.extPresent }
func BridgeMMEStatusTransferFieldExtWire(v *MMEStatusTransfer) *[]aper.WireSpan { return &v.extWire }
func BridgeMMEStatusTransferFieldPerExtPadding(v *MMEStatusTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMMEStatusTransferFieldPerPadding(v *MMEStatusTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMMEStatusTransferFieldProtocolIEsIndef(v *MMEStatusTransfer) *bool {
	return &v.protocolIEsIndef
}
func BridgeMMEStatusTransferFieldReceived(v *MMEStatusTransfer) *bool { return &v.received }
func BridgeMMEStatusTransferFieldReceivedAbsolute(v *MMEStatusTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeMMEStatusTransferFieldReceivedBytes(v *MMEStatusTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEStatusTransferFieldReceivedLocation(v *MMEStatusTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMEStatusTransferFieldReplay(v *MMEStatusTransfer) *aper.Snapshot { return &v.replay }
func BridgeMMEStatusTransferFieldStream(v *MMEStatusTransfer) *aper.WireSpan { return &v.stream }
func BridgeMMEStatusTransferFieldWithoutReplay(v *MMEStatusTransfer) *bool   { return &v.withoutReplay }
func BridgeMMEStatusTransferMethodMarshalAPERBudget(v *MMEStatusTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEStatusTransferMethodMarshalAPERBudgetValue(v *MMEStatusTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMMEStatusTransferMethodMarshalAPERChanged(v *MMEStatusTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMMEStatusTransferMethodMarshalAPERChangedValue(v *MMEStatusTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMMEStatusTransferMethodMarshalAPERLegacy(v *MMEStatusTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMMEStatusTransferMethodMarshalAPERNewValue(v *MMEStatusTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMMEStatusTransferMethodMarshalAPERPlanned(v *MMEStatusTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMMEStatusTransferMethodMarshalAPERTo(v *MMEStatusTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEStatusTransferMethodUnmarshalAPERFrom(v *MMEStatusTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEStatusTransferMethodUnmarshalAPERLegacy(v *MMEStatusTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMEStatusTransferMethodUnmarshalAPERWithOptions(v *MMEStatusTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMEStatusTransferValueCodecFieldCapture(v *MMEStatusTransferValueCodec) *func(MMEStatusTransfer, aper.DecodeState) (MMEStatusTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferValueCodecFieldCompare(v *MMEStatusTransferValueCodec) *func(MMEStatusTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferValueCodecFieldContext(v *MMEStatusTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferValueCodecFieldDecode(v *MMEStatusTransferValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransfer, error) {
	return &v.decode
}
func BridgeMMEStatusTransferValueCodecFieldEncode(v *MMEStatusTransferValueCodec) *func(MMEStatusTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferValueCodecFieldPath(v *MMEStatusTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferValueCodecMethodEncodeBudgetValue(v MMEStatusTransferValueCodec, a0 MMEStatusTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEStatusTransferValueCodecMethodEncodeChanged(v MMEStatusTransferValueCodec, a0 MMEStatusTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNASNonDeliveryIndicationAPERValueFieldContext(v *NASNonDeliveryIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationAPERValueFieldReceived(v *NASNonDeliveryIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNASNonDeliveryIndicationAPERValueFieldReplay(v *NASNonDeliveryIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationAPERValueFieldWithoutReplay(v *NASNonDeliveryIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNASNonDeliveryIndicationFieldExtCount(v *NASNonDeliveryIndication) *int64 {
	return &v.extCount
}
func BridgeNASNonDeliveryIndicationFieldExtData(v *NASNonDeliveryIndication) *[][]byte {
	return &v.extData
}
func BridgeNASNonDeliveryIndicationFieldExtOrigin(v *NASNonDeliveryIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNASNonDeliveryIndicationFieldExtPresent(v *NASNonDeliveryIndication) *[]bool {
	return &v.extPresent
}
func BridgeNASNonDeliveryIndicationFieldExtWire(v *NASNonDeliveryIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeNASNonDeliveryIndicationFieldPerExtPadding(v *NASNonDeliveryIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNASNonDeliveryIndicationFieldPerPadding(v *NASNonDeliveryIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNASNonDeliveryIndicationFieldProtocolIEsIndef(v *NASNonDeliveryIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeNASNonDeliveryIndicationFieldReceived(v *NASNonDeliveryIndication) *bool {
	return &v.received
}
func BridgeNASNonDeliveryIndicationFieldReceivedAbsolute(v *NASNonDeliveryIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeNASNonDeliveryIndicationFieldReceivedBytes(v *NASNonDeliveryIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNASNonDeliveryIndicationFieldReceivedLocation(v *NASNonDeliveryIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeNASNonDeliveryIndicationFieldReplay(v *NASNonDeliveryIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationFieldStream(v *NASNonDeliveryIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeNASNonDeliveryIndicationFieldWithoutReplay(v *NASNonDeliveryIndication) *bool {
	return &v.withoutReplay
}
func BridgeNASNonDeliveryIndicationMethodMarshalAPERBudget(v *NASNonDeliveryIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNASNonDeliveryIndicationMethodMarshalAPERBudgetValue(v *NASNonDeliveryIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNASNonDeliveryIndicationMethodMarshalAPERChanged(v *NASNonDeliveryIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationMethodMarshalAPERChangedValue(v *NASNonDeliveryIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationMethodMarshalAPERLegacy(v *NASNonDeliveryIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNASNonDeliveryIndicationMethodMarshalAPERNewValue(v *NASNonDeliveryIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNASNonDeliveryIndicationMethodMarshalAPERPlanned(v *NASNonDeliveryIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationMethodMarshalAPERTo(v *NASNonDeliveryIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNASNonDeliveryIndicationMethodUnmarshalAPERFrom(v *NASNonDeliveryIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNASNonDeliveryIndicationMethodUnmarshalAPERLegacy(v *NASNonDeliveryIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNASNonDeliveryIndicationMethodUnmarshalAPERWithOptions(v *NASNonDeliveryIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNASNonDeliveryIndicationValueCodecFieldCapture(v *NASNonDeliveryIndicationValueCodec) *func(NASNonDeliveryIndication, aper.DecodeState) (NASNonDeliveryIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeNASNonDeliveryIndicationValueCodecFieldCompare(v *NASNonDeliveryIndicationValueCodec) *func(NASNonDeliveryIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASNonDeliveryIndicationValueCodecFieldContext(v *NASNonDeliveryIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationValueCodecFieldDecode(v *NASNonDeliveryIndicationValueCodec) *func([]byte, aper.DecodeState) (NASNonDeliveryIndication, error) {
	return &v.decode
}
func BridgeNASNonDeliveryIndicationValueCodecFieldEncode(v *NASNonDeliveryIndicationValueCodec) *func(NASNonDeliveryIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASNonDeliveryIndicationValueCodecFieldPath(v *NASNonDeliveryIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASNonDeliveryIndicationValueCodecMethodEncodeBudgetValue(v NASNonDeliveryIndicationValueCodec, a0 NASNonDeliveryIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationValueCodecMethodEncodeChanged(v NASNonDeliveryIndicationValueCodec, a0 NASNonDeliveryIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateMessageIEsValueFieldId(v *PrivateMessageIEsValue) *s20.PrivateIEID { return &v.id }
func BridgePrivateMessageIEsValueFieldOpaque(v *PrivateMessageIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePrivateMessageIEsValueFieldValid(v *PrivateMessageIEsValue) *bool { return &v.valid }
func BridgePrivateMessageIEsValueMethodCaptureSemantics(v PrivateMessageIEsValue, a0 aper.SemanticCapture) PrivateMessageIEsValue {
	return v.captureSemantics(a0)
}
func BridgePrivateMessageIEsValueMethodCompareSemantics(v PrivateMessageIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePrivateMessageIEsValueMethodDecode(v PrivateMessageIEsValue, a0 s20.PrivateIEID, a1 aper.OpaqueOpenType) (PrivateMessageIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePrivateMessageIEsValueMethodEncode(v PrivateMessageIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgePrivateMessageIEsValueMethodEncodeFresh(v PrivateMessageIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePrivateMessageIEsValueMethodMatchesID(v PrivateMessageIEsValue, a0 s20.PrivateIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePrivateMessageIEsValueMethodRule(v PrivateMessageIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgePrivateMessageIEsValuePrivateIEContainerAPERValueFieldContext(v *PrivateMessageIEsValuePrivateIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageIEsValuePrivateIEContainerAPERValueFieldReceived(v *PrivateMessageIEsValuePrivateIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePrivateMessageIEsValuePrivateIEContainerAPERValueFieldReplay(v *PrivateMessageIEsValuePrivateIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePrivateMessageIEsValuePrivateIEContainerAPERValueFieldWithoutReplay(v *PrivateMessageIEsValuePrivateIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldCapture(v *PrivateMessageIEsValuePrivateIEContainerValueCodec) *func(PrivateMessageIEsValuePrivateIEContainer, aper.DecodeState) (PrivateMessageIEsValuePrivateIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldCompare(v *PrivateMessageIEsValuePrivateIEContainerValueCodec) *func(PrivateMessageIEsValuePrivateIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldContext(v *PrivateMessageIEsValuePrivateIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldDecode(v *PrivateMessageIEsValuePrivateIEContainerValueCodec) *func([]byte, aper.DecodeState) (PrivateMessageIEsValuePrivateIEContainer, error) {
	return &v.decode
}
func BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldEncode(v *PrivateMessageIEsValuePrivateIEContainerValueCodec) *func(PrivateMessageIEsValuePrivateIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldPath(v *PrivateMessageIEsValuePrivateIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePrivateMessageIEsValuePrivateIEContainerValueCodecMethodEncodeBudgetValue(v PrivateMessageIEsValuePrivateIEContainerValueCodec, a0 PrivateMessageIEsValuePrivateIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePrivateMessageIEsValuePrivateIEContainerValueCodecMethodEncodeChanged(v PrivateMessageIEsValuePrivateIEContainerValueCodec, a0 PrivateMessageIEsValuePrivateIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateMessageIEsValuePrivateIEFieldAPERValueFieldContext(v *PrivateMessageIEsValuePrivateIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageIEsValuePrivateIEFieldAPERValueFieldReceived(v *PrivateMessageIEsValuePrivateIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePrivateMessageIEsValuePrivateIEFieldAPERValueFieldReplay(v *PrivateMessageIEsValuePrivateIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePrivateMessageIEsValuePrivateIEFieldAPERValueFieldWithoutReplay(v *PrivateMessageIEsValuePrivateIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldReceived(v *PrivateMessageIEsValuePrivateIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v *PrivateMessageIEsValuePrivateIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldStream(v *PrivateMessageIEsValuePrivateIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v *PrivateMessageIEsValuePrivateIEField) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(v *PrivateMessageIEsValuePrivateIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(v *PrivateMessageIEsValuePrivateIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldCapture(v *PrivateMessageIEsValuePrivateIEFieldValueCodec) *func(PrivateMessageIEsValuePrivateIEField, aper.DecodeState) (PrivateMessageIEsValuePrivateIEField, aper.Snapshot) {
	return &v.capture
}
func BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldCompare(v *PrivateMessageIEsValuePrivateIEFieldValueCodec) *func(PrivateMessageIEsValuePrivateIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldContext(v *PrivateMessageIEsValuePrivateIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldDecode(v *PrivateMessageIEsValuePrivateIEFieldValueCodec) *func([]byte, aper.DecodeState) (PrivateMessageIEsValuePrivateIEField, error) {
	return &v.decode
}
func BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldEncode(v *PrivateMessageIEsValuePrivateIEFieldValueCodec) *func(PrivateMessageIEsValuePrivateIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldPath(v *PrivateMessageIEsValuePrivateIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePrivateMessageIEsValuePrivateIEFieldValueCodecMethodEncodeBudgetValue(v PrivateMessageIEsValuePrivateIEFieldValueCodec, a0 PrivateMessageIEsValuePrivateIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePrivateMessageIEsValuePrivateIEFieldValueCodecMethodEncodeChanged(v PrivateMessageIEsValuePrivateIEFieldValueCodec, a0 PrivateMessageIEsValuePrivateIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABToBeModifiedItemBearerModReqIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 36:
		if value, ok := v.AsERABToBeModifiedItemBearerModReq(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *PrivateMessageIEsValue) Selected() (any, bool) { return nil, false }
