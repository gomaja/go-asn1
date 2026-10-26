// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s29 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s29

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
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
	Id            s23.PrivateIEID
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
	if err := s23.BridgePrivateIEIDMethodMarshalAPERTo(&v.Id, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	if err := s23.BridgePrivateIEIDMethodUnmarshalAPERFrom(&v.Id, bb); err != nil {
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
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIESingleContainer(v *s18.ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIESingleContainer(v *s18.ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIESingleContainer(v *s18.ERABFailedToResumeItemResumeResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIESingleContainer(v *s18.ERABFailedToResumeItemResumeResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIESingleContainer(v *s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIESingleContainer(v *s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABItemIEValueCaptureS1APProtocolIESingleContainer(v *s19.ERABItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABItemIEValueCompareS1APProtocolIESingleContainer(v *s19.ERABItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIESingleContainer(v *s19.ERABModifyItemBearerModConfIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIESingleContainer(v *s19.ERABModifyItemBearerModConfIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIESingleContainer(v *s19.ERABModifyItemBearerModResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIESingleContainer(v *s19.ERABModifyItemBearerModResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(v *s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(v *s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIESingleContainer(v *s19.ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIESingleContainer(v *s19.ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIESingleContainer(v *s19.ERABSetupItemBearerSUResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIESingleContainer(v *s19.ERABSetupItemBearerSUResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIESingleContainer(v *s19.ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIESingleContainer(v *s19.ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIESingleContainer(v *s18.ERABDataForwardingItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolIESingleContainer(v *s18.ERABDataForwardingItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionContainer(v *s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionContainer(v *s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(v *s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(v *s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIESingleContainer(v *s20.ERABToBeSwitchedULItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIESingleContainer(v *s20.ERABToBeSwitchedULItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(v *s20.ERABUsageReportItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABUsageReportItemIEValueCompareS1APProtocolIESingleContainer(v *s20.ERABUsageReportItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABUsageReportItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainer(v *s21.HandoverCancelIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelIEValueCompareS1APProtocolIEContainer(v *s21.HandoverCancelIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *s26.HandoverCancelAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainer(v *s26.HandoverCancelAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainer(v *s26.HandoverFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverFailureIEValueCompareS1APProtocolIEContainer(v *s26.HandoverFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainer(v *s26.HandoverPreparationFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainer(v *s26.HandoverPreparationFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainer(v *s26.InitialContextSetupFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainer(v *s26.InitialContextSetupFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// ERABToBeModifiedItemBearerModReqIEContainer is ProtocolIE-Container {{E-RABToBeModifiedItemBearerModReqIEs}} of TS 36.413: a list of ERABToBeModifiedItemBearerModReqIEField values.
type ERABToBeModifiedItemBearerModReqIEContainer []ERABToBeModifiedItemBearerModReqIEField

// ERABDataForwardingItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABDataForwardingItemIEs}} codec of TS 36.413.
func ERABDataForwardingItemIEValueERABIEContainerListCodec(table s00.ERABDataForwardingItemIEValueIETable) s18.ERABDataForwardingItemIEValueERABIEContainerListValueCodec {
	codec := ERABDataForwardingItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABDataForwardingItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABDataForwardingItemIEValueERABIEContainerListValueCodec {
		sealed := s18.ERABDataForwardingItemIEValueERABIEContainerListValueCodec{}
		*s18.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABDataForwardingItemIEValueERABIEContainerList"
		*s18.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABDataForwardingItemIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABDataForwardingItemIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABDataForwardingItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABDataForwardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABDataForwardingItemIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABDataForwardingItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(&codec))(s18.ERABDataForwardingItemIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABDataForwardingItemIEValueERABIEContainerList, options aper.DecodeState) (s18.ERABDataForwardingItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABDataForwardingItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeReqIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABFailedToResumeItemResumeReqIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeReqIEValueERABIEContainerListCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable) s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeReqIEValueERABIEContainerList"
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedToResumeItemResumeReqIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeReqIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedToResumeItemResumeReqIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeResIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABFailedToResumeItemResumeResIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeResIEValueERABIEContainerListCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable) s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeResIEValueERABIEContainerList"
		*s18.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedToResumeItemResumeResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeResIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedToResumeItemResumeResIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABFailedtoSetupItemHOReqAckIEs}} codec of TS 36.413.
func ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable) s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec {
	codec := ERABFailedtoSetupItemHOReqAckIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec {
		sealed := s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec{}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList"
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedtoSetupItemHOReqAckIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedtoSetupItemHOReqAckIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, options aper.DecodeState) (s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABItemIEs}} codec of TS 36.413.
func ERABItemIEValueERABIEContainerListCodec(table s00.ERABItemIEValueIETable) s19.ERABItemIEValueERABIEContainerListValueCodec {
	codec := ERABItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABItemIEValueERABIEContainerListValueCodec {
		sealed := s19.ERABItemIEValueERABIEContainerListValueCodec{}
		*s19.BridgeERABItemIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABItemIEValueERABIEContainerList"
		*s19.BridgeERABItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABItemIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABItemIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABItemIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABItemIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABItemIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABItemIEContainerValueCodecFieldEncode(&codec))(s19.ERABItemIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABItemIEValueERABIEContainerList, options aper.DecodeState) (s19.ERABItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModConfIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABModifyItemBearerModConfIEs}} codec of TS 36.413.
func ERABModifyItemBearerModConfIEValueERABIEContainerListCodec(table s00.ERABModifyItemBearerModConfIEValueIETable) s19.ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec {
	codec := ERABModifyItemBearerModConfIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec {
		sealed := s19.ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec{}
		*s19.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModConfIEValueERABIEContainerList"
		*s19.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABModifyItemBearerModConfIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABModifyItemBearerModConfIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModConfIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABModifyItemBearerModConfIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(&codec))(s19.ERABModifyItemBearerModConfIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModConfIEValueERABIEContainerList, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModConfIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModResIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABModifyItemBearerModResIEs}} codec of TS 36.413.
func ERABModifyItemBearerModResIEValueERABIEContainerListCodec(table s00.ERABModifyItemBearerModResIEValueIETable) s19.ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec {
	codec := ERABModifyItemBearerModResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec {
		sealed := s19.ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec{}
		*s19.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModResIEValueERABIEContainerList"
		*s19.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABModifyItemBearerModResIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABModifyItemBearerModResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModResIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABModifyItemBearerModResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(&codec))(s19.ERABModifyItemBearerModResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModResIEValueERABIEContainerList, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABNotToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable) s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec {
	codec := ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec {
		sealed := s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec{}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList"
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABNotToBeModifiedItemBearerModIndIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s19.ERABNotToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABReleaseItemBearerRelCompIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompIEValueERABIEContainerListCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable) s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec {
	codec := ERABReleaseItemBearerRelCompIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec {
		sealed := s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec{}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseItemBearerRelCompIEValueERABIEContainerList"
		*s19.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABReleaseItemBearerRelCompIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseItemBearerRelCompIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(&codec))(s19.ERABReleaseItemBearerRelCompIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABSetupItemBearerSUResIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResIEValueERABIEContainerListCodec(table s00.ERABSetupItemBearerSUResIEValueIETable) s19.ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec {
	codec := ERABSetupItemBearerSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec {
		sealed := s19.ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec{}
		*s19.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupItemBearerSUResIEValueERABIEContainerList"
		*s19.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABSetupItemBearerSUResIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABSetupItemBearerSUResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemBearerSUResIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABSetupItemBearerSUResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(&codec))(s19.ERABSetupItemBearerSUResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemBearerSUResIEValueERABIEContainerList, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemBearerSUResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABSetupItemCtxtSUResIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResIEValueERABIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s19.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec {
		sealed := s19.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec{}
		*s19.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupItemCtxtSUResIEValueERABIEContainerList"
		*s19.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABSetupItemCtxtSUResIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABSetupItemCtxtSUResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemCtxtSUResIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABSetupItemCtxtSUResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s19.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEValueERABIEContainerList, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable) s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModIndIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec {
		sealed := s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec{}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList"
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABToBeModifiedItemBearerModIndIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s20.ERABToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListValueCodec{path: "ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeModifiedItemBearerModReqIEField
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
			return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeModifiedItemBearerModReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ERABToBeModifiedItemBearerModReqIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ERABToBeSwitchedULItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABToBeSwitchedULItemIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemIEValueERABIEContainerListCodec(table s00.ERABToBeSwitchedULItemIEValueIETable) s20.ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec {
	codec := ERABToBeSwitchedULItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec {
		sealed := s20.ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec{}
		*s20.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULItemIEValueERABIEContainerList"
		*s20.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABToBeSwitchedULItemIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABToBeSwitchedULItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULItemIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABToBeSwitchedULItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(&codec))(s20.ERABToBeSwitchedULItemIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeSwitchedULItemIEValueERABIEContainerList, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeSwitchedULItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABUsageReportItemIEs}} codec of TS 36.413.
func ERABUsageReportItemIEValueERABIEContainerListCodec(table s00.ERABUsageReportItemIEValueIETable) s20.ERABUsageReportItemIEValueERABIEContainerListValueCodec {
	codec := ERABUsageReportItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABUsageReportItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABUsageReportItemIEValueERABIEContainerListValueCodec {
		sealed := s20.ERABUsageReportItemIEValueERABIEContainerListValueCodec{}
		*s20.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABUsageReportItemIEValueERABIEContainerList"
		*s20.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABUsageReportItemIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABUsageReportItemIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABUsageReportItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABUsageReportItemIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABUsageReportItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(&codec))(s20.ERABUsageReportItemIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABUsageReportItemIEValueERABIEContainerList, options aper.DecodeState) (s20.ERABUsageReportItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s20.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABUsageReportItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverCancelAcknowledgeIEs}} codec of TS 36.413.
func HandoverCancelAcknowledgeIEValueERABIEContainerListCodec(table s00.HandoverCancelAcknowledgeIEValueIETable) s26.HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := HandoverCancelAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec {
		sealed := s26.HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec{}
		*s26.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "HandoverCancelAcknowledgeIEValueERABIEContainerList"
		*s26.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverCancelAcknowledgeIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverCancelAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelAcknowledgeIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverCancelAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.HandoverCancelAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverCancelAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverCancelAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverCancelIEs}} codec of TS 36.413.
func HandoverCancelIEValueERABIEContainerListCodec(table s00.HandoverCancelIEValueIETable) s21.HandoverCancelIEValueERABIEContainerListValueCodec {
	codec := HandoverCancelIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.HandoverCancelIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s21.HandoverCancelIEValueERABIEContainerListValueCodec {
		sealed := s21.HandoverCancelIEValueERABIEContainerListValueCodec{}
		*s21.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "HandoverCancelIEValueERABIEContainerList"
		*s21.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.HandoverCancelIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.HandoverCancelIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.HandoverCancelIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverCancelIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverCancelIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s21.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.HandoverCancelIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeHandoverCancelIEContainerValueCodecFieldEncode(&codec))(s21.HandoverCancelIEContainer(value), fresh, budget)
		}
		*s21.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.HandoverCancelIEValueERABIEContainerList, options aper.DecodeState) (s21.HandoverCancelIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s21.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.HandoverCancelIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverFailureIEs}} codec of TS 36.413.
func HandoverFailureIEValueERABIEContainerListCodec(table s00.HandoverFailureIEValueIETable) s26.HandoverFailureIEValueERABIEContainerListValueCodec {
	codec := HandoverFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverFailureIEValueERABIEContainerListValueCodec {
		sealed := s26.HandoverFailureIEValueERABIEContainerListValueCodec{}
		*s26.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "HandoverFailureIEValueERABIEContainerList"
		*s26.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverFailureIEContainerValueCodecFieldEncode(&codec))(s26.HandoverFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverFailureIEValueERABIEContainerList, options aper.DecodeState) (s26.HandoverFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverPreparationFailureIEs}} codec of TS 36.413.
func HandoverPreparationFailureIEValueERABIEContainerListCodec(table s00.HandoverPreparationFailureIEValueIETable) s26.HandoverPreparationFailureIEValueERABIEContainerListValueCodec {
	codec := HandoverPreparationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverPreparationFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverPreparationFailureIEValueERABIEContainerListValueCodec {
		sealed := s26.HandoverPreparationFailureIEValueERABIEContainerListValueCodec{}
		*s26.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "HandoverPreparationFailureIEValueERABIEContainerList"
		*s26.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverPreparationFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverPreparationFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverPreparationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverPreparationFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverPreparationFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(&codec))(s26.HandoverPreparationFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverPreparationFailureIEValueERABIEContainerList, options aper.DecodeState) (s26.HandoverPreparationFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverPreparationFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifyItemBearerModReqExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABToBeModifyItemBearerModReqExtIEs}} codec of TS 36.413.
func ERABToBeModifyItemBearerModReqExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable) s24.ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeModifyItemBearerModReqExtIEsValueExtensionTableFieldBound(&table) {
		return s24.ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec{}
	}
	return func() s24.ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec {
		sealed := s24.ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec{}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABToBeModifyItemBearerModReqExtIEsExtField"
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.ERABToBeModifyItemBearerModReqExtIEsExtField, error) {
			var field s24.ERABToBeModifyItemBearerModReqExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeModifyItemBearerModReqExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifyItemBearerModReqExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeModifyItemBearerModReqExtIEsExtField")
			}
			return field, nil
		}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s24.ERABToBeModifyItemBearerModReqExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s24.ERABToBeModifyItemBearerModReqExtIEsExtField, options aper.DecodeState) (s24.ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s24.ERABToBeModifyItemBearerModReqExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifyItemBearerModReqExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABToBeModifyItemBearerModReqExtIEs}} codec of TS 36.413.
func ERABToBeModifyItemBearerModReqExtIEsValueExtensionTableCodec(table s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable, bounds aper.ListBounds) s24.ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeModifyItemBearerModReqExtIEsValueExtensionTableFieldBound(&table) {
		return s24.ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s24.ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec {
		sealed := s24.ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec{}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABToBeModifyItemBearerModReqExtIEsExtContainer"
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.ERABToBeModifyItemBearerModReqExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifyItemBearerModReqExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifyItemBearerModReqExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifyItemBearerModReqExtIEsExtContainer")
			}
			return fields, nil
		}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer, options aper.DecodeState) (s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABDataForwardingItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABDataForwardingItemIEs}} codec of TS 36.413.
func ERABDataForwardingItemIEValueIEFieldTableCodec(table s00.ERABDataForwardingItemIEValueIETable) s18.ERABDataForwardingItemIEFieldValueCodec {
	if !*s00.BridgeERABDataForwardingItemIEValueIETableFieldBound(&table) {
		return s18.ERABDataForwardingItemIEFieldValueCodec{}
	}
	return func() s18.ERABDataForwardingItemIEFieldValueCodec {
		sealed := s18.ERABDataForwardingItemIEFieldValueCodec{}
		*s18.BridgeERABDataForwardingItemIEFieldValueCodecFieldPath(&sealed) = "ERABDataForwardingItemIEField"
		*s18.BridgeERABDataForwardingItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABDataForwardingItemIEField, error) {
			var field s18.ERABDataForwardingItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s18.BridgeERABDataForwardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABDataForwardingItemIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEField")
			}
			return field, nil
		}
		*s18.BridgeERABDataForwardingItemIEFieldValueCodecFieldEncode(&sealed) = func(field s18.ERABDataForwardingItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s18.BridgeERABDataForwardingItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s18.BridgeERABDataForwardingItemIEFieldValueCodecFieldCapture(&sealed) = func(v s18.ERABDataForwardingItemIEField, options aper.DecodeState) (s18.ERABDataForwardingItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABDataForwardingItemIEFieldValueCodecFieldCompare(&sealed) = func(v s18.ERABDataForwardingItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABDataForwardingItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeReqIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABFailedToResumeItemResumeReqIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeReqIEValueIEFieldTableCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable) s18.ERABFailedToResumeItemResumeReqIEFieldValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeReqIEValueIETableFieldBound(&table) {
		return s18.ERABFailedToResumeItemResumeReqIEFieldValueCodec{}
	}
	return func() s18.ERABFailedToResumeItemResumeReqIEFieldValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeReqIEFieldValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeReqIEField"
		*s18.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEField, error) {
			var field s18.ERABFailedToResumeItemResumeReqIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeReqIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEField")
			}
			return field, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldEncode(&sealed) = func(field s18.ERABFailedToResumeItemResumeReqIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEField, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeResIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABFailedToResumeItemResumeResIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeResIEValueIEFieldTableCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable) s18.ERABFailedToResumeItemResumeResIEFieldValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeResIEValueIETableFieldBound(&table) {
		return s18.ERABFailedToResumeItemResumeResIEFieldValueCodec{}
	}
	return func() s18.ERABFailedToResumeItemResumeResIEFieldValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeResIEFieldValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeResIEField"
		*s18.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEField, error) {
			var field s18.ERABFailedToResumeItemResumeResIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeResIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEField")
			}
			return field, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldEncode(&sealed) = func(field s18.ERABFailedToResumeItemResumeResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEField, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedtoSetupItemHOReqAckIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABFailedtoSetupItemHOReqAckIEs}} codec of TS 36.413.
func ERABFailedtoSetupItemHOReqAckIEValueIEFieldTableCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable) s18.ERABFailedtoSetupItemHOReqAckIEFieldValueCodec {
	if !*s00.BridgeERABFailedtoSetupItemHOReqAckIEValueIETableFieldBound(&table) {
		return s18.ERABFailedtoSetupItemHOReqAckIEFieldValueCodec{}
	}
	return func() s18.ERABFailedtoSetupItemHOReqAckIEFieldValueCodec {
		sealed := s18.ERABFailedtoSetupItemHOReqAckIEFieldValueCodec{}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldPath(&sealed) = "ERABFailedtoSetupItemHOReqAckIEField"
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedtoSetupItemHOReqAckIEField, error) {
			var field s18.ERABFailedtoSetupItemHOReqAckIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedtoSetupItemHOReqAckIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEField")
			}
			return field, nil
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldEncode(&sealed) = func(field s18.ERABFailedtoSetupItemHOReqAckIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedtoSetupItemHOReqAckIEField, options aper.DecodeState) (s18.ERABFailedtoSetupItemHOReqAckIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedtoSetupItemHOReqAckIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABItemIEs}} codec of TS 36.413.
func ERABItemIEValueIEFieldTableCodec(table s00.ERABItemIEValueIETable) s19.ERABItemIEFieldValueCodec {
	if !*s00.BridgeERABItemIEValueIETableFieldBound(&table) {
		return s19.ERABItemIEFieldValueCodec{}
	}
	return func() s19.ERABItemIEFieldValueCodec {
		sealed := s19.ERABItemIEFieldValueCodec{}
		*s19.BridgeERABItemIEFieldValueCodecFieldPath(&sealed) = "ERABItemIEField"
		*s19.BridgeERABItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABItemIEField, error) {
			var field s19.ERABItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s19.BridgeERABItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABItemIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABItemIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABItemIEField")
			}
			return field, nil
		}
		*s19.BridgeERABItemIEFieldValueCodecFieldEncode(&sealed) = func(field s19.ERABItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s19.BridgeERABItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeERABItemIEFieldValueCodecFieldCapture(&sealed) = func(v s19.ERABItemIEField, options aper.DecodeState) (s19.ERABItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABItemIEFieldValueCodecFieldCompare(&sealed) = func(v s19.ERABItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModConfIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABModifyItemBearerModConfIEs}} codec of TS 36.413.
func ERABModifyItemBearerModConfIEValueIEFieldTableCodec(table s00.ERABModifyItemBearerModConfIEValueIETable) s19.ERABModifyItemBearerModConfIEFieldValueCodec {
	if !*s00.BridgeERABModifyItemBearerModConfIEValueIETableFieldBound(&table) {
		return s19.ERABModifyItemBearerModConfIEFieldValueCodec{}
	}
	return func() s19.ERABModifyItemBearerModConfIEFieldValueCodec {
		sealed := s19.ERABModifyItemBearerModConfIEFieldValueCodec{}
		*s19.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModConfIEField"
		*s19.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEField, error) {
			var field s19.ERABModifyItemBearerModConfIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s19.BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModConfIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEField")
			}
			return field, nil
		}
		*s19.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldEncode(&sealed) = func(field s19.ERABModifyItemBearerModConfIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s19.BridgeERABModifyItemBearerModConfIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModConfIEField, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModConfIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModResIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABModifyItemBearerModResIEs}} codec of TS 36.413.
func ERABModifyItemBearerModResIEValueIEFieldTableCodec(table s00.ERABModifyItemBearerModResIEValueIETable) s19.ERABModifyItemBearerModResIEFieldValueCodec {
	if !*s00.BridgeERABModifyItemBearerModResIEValueIETableFieldBound(&table) {
		return s19.ERABModifyItemBearerModResIEFieldValueCodec{}
	}
	return func() s19.ERABModifyItemBearerModResIEFieldValueCodec {
		sealed := s19.ERABModifyItemBearerModResIEFieldValueCodec{}
		*s19.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModResIEField"
		*s19.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEField, error) {
			var field s19.ERABModifyItemBearerModResIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s19.BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModResIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEField")
			}
			return field, nil
		}
		*s19.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldEncode(&sealed) = func(field s19.ERABModifyItemBearerModResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s19.BridgeERABModifyItemBearerModResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModResIEField, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABNotToBeModifiedItemBearerModIndIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABNotToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABNotToBeModifiedItemBearerModIndIEValueIEFieldTableCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable) s19.ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec {
	if !*s00.BridgeERABNotToBeModifiedItemBearerModIndIEValueIETableFieldBound(&table) {
		return s19.ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec{}
	}
	return func() s19.ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec {
		sealed := s19.ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec{}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedItemBearerModIndIEField"
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEField, error) {
			var field s19.ERABNotToBeModifiedItemBearerModIndIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedItemBearerModIndIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEField")
			}
			return field, nil
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldEncode(&sealed) = func(field s19.ERABNotToBeModifiedItemBearerModIndIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldCapture(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEField, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldCompare(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABReleaseItemBearerRelCompIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompIEValueIEFieldTableCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable) s19.ERABReleaseItemBearerRelCompIEFieldValueCodec {
	if !*s00.BridgeERABReleaseItemBearerRelCompIEValueIETableFieldBound(&table) {
		return s19.ERABReleaseItemBearerRelCompIEFieldValueCodec{}
	}
	return func() s19.ERABReleaseItemBearerRelCompIEFieldValueCodec {
		sealed := s19.ERABReleaseItemBearerRelCompIEFieldValueCodec{}
		*s19.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldPath(&sealed) = "ERABReleaseItemBearerRelCompIEField"
		*s19.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEField, error) {
			var field s19.ERABReleaseItemBearerRelCompIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s19.BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseItemBearerRelCompIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEField")
			}
			return field, nil
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldEncode(&sealed) = func(field s19.ERABReleaseItemBearerRelCompIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s19.BridgeERABReleaseItemBearerRelCompIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldCapture(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEField, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldCompare(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABSetupItemBearerSUResIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResIEValueIEFieldTableCodec(table s00.ERABSetupItemBearerSUResIEValueIETable) s19.ERABSetupItemBearerSUResIEFieldValueCodec {
	if !*s00.BridgeERABSetupItemBearerSUResIEValueIETableFieldBound(&table) {
		return s19.ERABSetupItemBearerSUResIEFieldValueCodec{}
	}
	return func() s19.ERABSetupItemBearerSUResIEFieldValueCodec {
		sealed := s19.ERABSetupItemBearerSUResIEFieldValueCodec{}
		*s19.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldPath(&sealed) = "ERABSetupItemBearerSUResIEField"
		*s19.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEField, error) {
			var field s19.ERABSetupItemBearerSUResIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s19.BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemBearerSUResIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEField")
			}
			return field, nil
		}
		*s19.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldEncode(&sealed) = func(field s19.ERABSetupItemBearerSUResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s19.BridgeERABSetupItemBearerSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemBearerSUResIEField, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemBearerSUResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABSetupItemCtxtSUResIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResIEValueIEFieldTableCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s19.ERABSetupItemCtxtSUResIEFieldValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResIEValueIETableFieldBound(&table) {
		return s19.ERABSetupItemCtxtSUResIEFieldValueCodec{}
	}
	return func() s19.ERABSetupItemCtxtSUResIEFieldValueCodec {
		sealed := s19.ERABSetupItemCtxtSUResIEFieldValueCodec{}
		*s19.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldPath(&sealed) = "ERABSetupItemCtxtSUResIEField"
		*s19.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEField, error) {
			var field s19.ERABSetupItemCtxtSUResIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s19.BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemCtxtSUResIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEField")
			}
			return field, nil
		}
		*s19.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldEncode(&sealed) = func(field s19.ERABSetupItemCtxtSUResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s19.BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s19.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEField, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndIEValueIEFieldTableCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable) s20.ERABToBeModifiedItemBearerModIndIEFieldValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModIndIEValueIETableFieldBound(&table) {
		return s20.ERABToBeModifiedItemBearerModIndIEFieldValueCodec{}
	}
	return func() s20.ERABToBeModifiedItemBearerModIndIEFieldValueCodec {
		sealed := s20.ERABToBeModifiedItemBearerModIndIEFieldValueCodec{}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldPath(&sealed) = "ERABToBeModifiedItemBearerModIndIEField"
		*s20.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEField, error) {
			var field s20.ERABToBeModifiedItemBearerModIndIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s20.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModIndIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEField")
			}
			return field, nil
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldEncode(&sealed) = func(field s20.ERABToBeModifiedItemBearerModIndIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s20.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEField, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return ERABToBeModifiedItemBearerModReqIEFieldValueCodec{path: "ERABToBeModifiedItemBearerModReqIEField", decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEField, error) {
		var field ERABToBeModifiedItemBearerModReqIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModReqIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEField")
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
		BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
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
func ERABToBeSwitchedULItemIEValueIEFieldTableCodec(table s00.ERABToBeSwitchedULItemIEValueIETable) s20.ERABToBeSwitchedULItemIEFieldValueCodec {
	if !*s00.BridgeERABToBeSwitchedULItemIEValueIETableFieldBound(&table) {
		return s20.ERABToBeSwitchedULItemIEFieldValueCodec{}
	}
	return func() s20.ERABToBeSwitchedULItemIEFieldValueCodec {
		sealed := s20.ERABToBeSwitchedULItemIEFieldValueCodec{}
		*s20.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULItemIEField"
		*s20.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEField, error) {
			var field s20.ERABToBeSwitchedULItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s20.BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULItemIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEField")
			}
			return field, nil
		}
		*s20.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldEncode(&sealed) = func(field s20.ERABToBeSwitchedULItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s20.BridgeERABToBeSwitchedULItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s20.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeSwitchedULItemIEField, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeSwitchedULItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABUsageReportItemIEs}} codec of TS 36.413.
func ERABUsageReportItemIEValueIEFieldTableCodec(table s00.ERABUsageReportItemIEValueIETable) s20.ERABUsageReportItemIEFieldValueCodec {
	if !*s00.BridgeERABUsageReportItemIEValueIETableFieldBound(&table) {
		return s20.ERABUsageReportItemIEFieldValueCodec{}
	}
	return func() s20.ERABUsageReportItemIEFieldValueCodec {
		sealed := s20.ERABUsageReportItemIEFieldValueCodec{}
		*s20.BridgeERABUsageReportItemIEFieldValueCodecFieldPath(&sealed) = "ERABUsageReportItemIEField"
		*s20.BridgeERABUsageReportItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABUsageReportItemIEField, error) {
			var field s20.ERABUsageReportItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s20.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABUsageReportItemIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABUsageReportItemIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABUsageReportItemIEField")
			}
			return field, nil
		}
		*s20.BridgeERABUsageReportItemIEFieldValueCodecFieldEncode(&sealed) = func(field s20.ERABUsageReportItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s20.BridgeERABUsageReportItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s20.BridgeERABUsageReportItemIEFieldValueCodecFieldCapture(&sealed) = func(v s20.ERABUsageReportItemIEField, options aper.DecodeState) (s20.ERABUsageReportItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABUsageReportItemIEFieldValueCodecFieldCompare(&sealed) = func(v s20.ERABUsageReportItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABUsageReportItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverCancelAcknowledgeIEs}} codec of TS 36.413.
func HandoverCancelAcknowledgeIEValueIEFieldTableCodec(table s00.HandoverCancelAcknowledgeIEValueIETable) s26.HandoverCancelAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeHandoverCancelAcknowledgeIEValueIETableFieldBound(&table) {
		return s26.HandoverCancelAcknowledgeIEFieldValueCodec{}
	}
	return func() s26.HandoverCancelAcknowledgeIEFieldValueCodec {
		sealed := s26.HandoverCancelAcknowledgeIEFieldValueCodec{}
		*s26.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldPath(&sealed) = "HandoverCancelAcknowledgeIEField"
		*s26.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEField, error) {
			var field s26.HandoverCancelAcknowledgeIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelAcknowledgeIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEField")
			}
			return field, nil
		}
		*s26.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldEncode(&sealed) = func(field s26.HandoverCancelAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldCapture(&sealed) = func(v s26.HandoverCancelAcknowledgeIEField, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldCompare(&sealed) = func(v s26.HandoverCancelAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverCancelIEs}} codec of TS 36.413.
func HandoverCancelIEValueIEFieldTableCodec(table s00.HandoverCancelIEValueIETable) s21.HandoverCancelIEFieldValueCodec {
	if !*s00.BridgeHandoverCancelIEValueIETableFieldBound(&table) {
		return s21.HandoverCancelIEFieldValueCodec{}
	}
	return func() s21.HandoverCancelIEFieldValueCodec {
		sealed := s21.HandoverCancelIEFieldValueCodec{}
		*s21.BridgeHandoverCancelIEFieldValueCodecFieldPath(&sealed) = "HandoverCancelIEField"
		*s21.BridgeHandoverCancelIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.HandoverCancelIEField, error) {
			var field s21.HandoverCancelIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s21.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverCancelIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverCancelIEField")
			}
			return field, nil
		}
		*s21.BridgeHandoverCancelIEFieldValueCodecFieldEncode(&sealed) = func(field s21.HandoverCancelIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s21.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s21.BridgeHandoverCancelIEFieldValueCodecFieldCapture(&sealed) = func(v s21.HandoverCancelIEField, options aper.DecodeState) (s21.HandoverCancelIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeHandoverCancelIEFieldValueCodecFieldCompare(&sealed) = func(v s21.HandoverCancelIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeHandoverCancelIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverFailureIEs}} codec of TS 36.413.
func HandoverFailureIEValueIEFieldTableCodec(table s00.HandoverFailureIEValueIETable) s26.HandoverFailureIEFieldValueCodec {
	if !*s00.BridgeHandoverFailureIEValueIETableFieldBound(&table) {
		return s26.HandoverFailureIEFieldValueCodec{}
	}
	return func() s26.HandoverFailureIEFieldValueCodec {
		sealed := s26.HandoverFailureIEFieldValueCodec{}
		*s26.BridgeHandoverFailureIEFieldValueCodecFieldPath(&sealed) = "HandoverFailureIEField"
		*s26.BridgeHandoverFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverFailureIEField, error) {
			var field s26.HandoverFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s26.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverFailureIEField")
			}
			return field, nil
		}
		*s26.BridgeHandoverFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s26.HandoverFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s26.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeHandoverFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s26.HandoverFailureIEField, options aper.DecodeState) (s26.HandoverFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s26.HandoverFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverPreparationFailureIEs}} codec of TS 36.413.
func HandoverPreparationFailureIEValueIEFieldTableCodec(table s00.HandoverPreparationFailureIEValueIETable) s26.HandoverPreparationFailureIEFieldValueCodec {
	if !*s00.BridgeHandoverPreparationFailureIEValueIETableFieldBound(&table) {
		return s26.HandoverPreparationFailureIEFieldValueCodec{}
	}
	return func() s26.HandoverPreparationFailureIEFieldValueCodec {
		sealed := s26.HandoverPreparationFailureIEFieldValueCodec{}
		*s26.BridgeHandoverPreparationFailureIEFieldValueCodecFieldPath(&sealed) = "HandoverPreparationFailureIEField"
		*s26.BridgeHandoverPreparationFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverPreparationFailureIEField, error) {
			var field s26.HandoverPreparationFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s26.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverPreparationFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEField")
			}
			return field, nil
		}
		*s26.BridgeHandoverPreparationFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s26.HandoverPreparationFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s26.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeHandoverPreparationFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s26.HandoverPreparationFailureIEField, options aper.DecodeState) (s26.HandoverPreparationFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverPreparationFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s26.HandoverPreparationFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverPreparationFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{InitialContextSetupFailureIEs}} codec of TS 36.413.
func InitialContextSetupFailureIEValueIEFieldTableCodec(table s00.InitialContextSetupFailureIEValueIETable) s26.InitialContextSetupFailureIEFieldValueCodec {
	if !*s00.BridgeInitialContextSetupFailureIEValueIETableFieldBound(&table) {
		return s26.InitialContextSetupFailureIEFieldValueCodec{}
	}
	return func() s26.InitialContextSetupFailureIEFieldValueCodec {
		sealed := s26.InitialContextSetupFailureIEFieldValueCodec{}
		*s26.BridgeInitialContextSetupFailureIEFieldValueCodecFieldPath(&sealed) = "InitialContextSetupFailureIEField"
		*s26.BridgeInitialContextSetupFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.InitialContextSetupFailureIEField, error) {
			var field s26.InitialContextSetupFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s26.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEField")
			}
			return field, nil
		}
		*s26.BridgeInitialContextSetupFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s26.InitialContextSetupFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s26.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeInitialContextSetupFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s26.InitialContextSetupFailureIEField, options aper.DecodeState) (s26.InitialContextSetupFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeInitialContextSetupFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s26.InitialContextSetupFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeInitialContextSetupFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABDataForwardingItemIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABDataForwardingItemIEs}} codec of TS 36.413.
func ERABDataForwardingItemIEValueIETableCodec(table s00.ERABDataForwardingItemIEValueIETable, bounds aper.ListBounds) s18.ERABDataForwardingItemIEContainerValueCodec {
	if !*s00.BridgeERABDataForwardingItemIEValueIETableFieldBound(&table) {
		return s18.ERABDataForwardingItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABDataForwardingItemIEContainerValueCodec {
		sealed := s18.ERABDataForwardingItemIEContainerValueCodec{}
		*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldPath(&sealed) = "ERABDataForwardingItemIEContainer"
		*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABDataForwardingItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABDataForwardingItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABDataForwardingItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABDataForwardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABDataForwardingItemIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEContainer")
			}
			return fields, nil
		}
		*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s18.ERABDataForwardingItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s18.BridgeERABDataForwardingItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldCapture(&sealed) = func(v s18.ERABDataForwardingItemIEContainer, options aper.DecodeState) (s18.ERABDataForwardingItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldCompare(&sealed) = func(v s18.ERABDataForwardingItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeReqIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABFailedToResumeItemResumeReqIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeReqIEValueIETableCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable, bounds aper.ListBounds) s18.ERABFailedToResumeItemResumeReqIEContainerValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeReqIEValueIETableFieldBound(&table) {
		return s18.ERABFailedToResumeItemResumeReqIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedToResumeItemResumeReqIEContainerValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeReqIEContainerValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeReqIEContainer"
		*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedToResumeItemResumeReqIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedToResumeItemResumeReqIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeReqIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEContainer")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(&sealed) = func(fields s18.ERABFailedToResumeItemResumeReqIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEContainer, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeResIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABFailedToResumeItemResumeResIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeResIEValueIETableCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable, bounds aper.ListBounds) s18.ERABFailedToResumeItemResumeResIEContainerValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeResIEValueIETableFieldBound(&table) {
		return s18.ERABFailedToResumeItemResumeResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedToResumeItemResumeResIEContainerValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeResIEContainerValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeResIEContainer"
		*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedToResumeItemResumeResIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedToResumeItemResumeResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeResIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEContainer")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldEncode(&sealed) = func(fields s18.ERABFailedToResumeItemResumeResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEContainer, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedtoSetupItemHOReqAckIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABFailedtoSetupItemHOReqAckIEs}} codec of TS 36.413.
func ERABFailedtoSetupItemHOReqAckIEValueIETableCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable, bounds aper.ListBounds) s18.ERABFailedtoSetupItemHOReqAckIEContainerValueCodec {
	if !*s00.BridgeERABFailedtoSetupItemHOReqAckIEValueIETableFieldBound(&table) {
		return s18.ERABFailedtoSetupItemHOReqAckIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedtoSetupItemHOReqAckIEContainerValueCodec {
		sealed := s18.ERABFailedtoSetupItemHOReqAckIEContainerValueCodec{}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldPath(&sealed) = "ERABFailedtoSetupItemHOReqAckIEContainer"
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedtoSetupItemHOReqAckIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedtoSetupItemHOReqAckIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedtoSetupItemHOReqAckIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedtoSetupItemHOReqAckIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEContainer")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(&sealed) = func(fields s18.ERABFailedtoSetupItemHOReqAckIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedtoSetupItemHOReqAckIEContainer, options aper.DecodeState) (s18.ERABFailedtoSetupItemHOReqAckIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedtoSetupItemHOReqAckIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABItemIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABItemIEs}} codec of TS 36.413.
func ERABItemIEValueIETableCodec(table s00.ERABItemIEValueIETable, bounds aper.ListBounds) s19.ERABItemIEContainerValueCodec {
	if !*s00.BridgeERABItemIEValueIETableFieldBound(&table) {
		return s19.ERABItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABItemIEContainerValueCodec {
		sealed := s19.ERABItemIEContainerValueCodec{}
		*s19.BridgeERABItemIEContainerValueCodecFieldPath(&sealed) = "ERABItemIEContainer"
		*s19.BridgeERABItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABItemIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABItemIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABItemIEContainer")
			}
			return fields, nil
		}
		*s19.BridgeERABItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s19.ERABItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s19.BridgeERABItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s19.BridgeERABItemIEContainerValueCodecFieldCapture(&sealed) = func(v s19.ERABItemIEContainer, options aper.DecodeState) (s19.ERABItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABItemIEContainerValueCodecFieldCompare(&sealed) = func(v s19.ERABItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModConfIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABModifyItemBearerModConfIEs}} codec of TS 36.413.
func ERABModifyItemBearerModConfIEValueIETableCodec(table s00.ERABModifyItemBearerModConfIEValueIETable, bounds aper.ListBounds) s19.ERABModifyItemBearerModConfIEContainerValueCodec {
	if !*s00.BridgeERABModifyItemBearerModConfIEValueIETableFieldBound(&table) {
		return s19.ERABModifyItemBearerModConfIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABModifyItemBearerModConfIEContainerValueCodec {
		sealed := s19.ERABModifyItemBearerModConfIEContainerValueCodec{}
		*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModConfIEContainer"
		*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABModifyItemBearerModConfIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABModifyItemBearerModConfIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModConfIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEContainer")
			}
			return fields, nil
		}
		*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(&sealed) = func(fields s19.ERABModifyItemBearerModConfIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s19.BridgeERABModifyItemBearerModConfIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModConfIEContainer, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModConfIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModResIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABModifyItemBearerModResIEs}} codec of TS 36.413.
func ERABModifyItemBearerModResIEValueIETableCodec(table s00.ERABModifyItemBearerModResIEValueIETable, bounds aper.ListBounds) s19.ERABModifyItemBearerModResIEContainerValueCodec {
	if !*s00.BridgeERABModifyItemBearerModResIEValueIETableFieldBound(&table) {
		return s19.ERABModifyItemBearerModResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABModifyItemBearerModResIEContainerValueCodec {
		sealed := s19.ERABModifyItemBearerModResIEContainerValueCodec{}
		*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModResIEContainer"
		*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABModifyItemBearerModResIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABModifyItemBearerModResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModResIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEContainer")
			}
			return fields, nil
		}
		*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(&sealed) = func(fields s19.ERABModifyItemBearerModResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s19.BridgeERABModifyItemBearerModResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModResIEContainer, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABNotToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s19.ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec {
	if !*s00.BridgeERABNotToBeModifiedItemBearerModIndIEValueIETableFieldBound(&table) {
		return s19.ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec {
		sealed := s19.ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec{}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedItemBearerModIndIEContainer"
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABNotToBeModifiedItemBearerModIndIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABNotToBeModifiedItemBearerModIndIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedItemBearerModIndIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEContainer")
			}
			return fields, nil
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&sealed) = func(fields s19.ERABNotToBeModifiedItemBearerModIndIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldCapture(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEContainer, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldCompare(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABReleaseItemBearerRelCompIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompIEValueIETableCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable, bounds aper.ListBounds) s19.ERABReleaseItemBearerRelCompIEContainerValueCodec {
	if !*s00.BridgeERABReleaseItemBearerRelCompIEValueIETableFieldBound(&table) {
		return s19.ERABReleaseItemBearerRelCompIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABReleaseItemBearerRelCompIEContainerValueCodec {
		sealed := s19.ERABReleaseItemBearerRelCompIEContainerValueCodec{}
		*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldPath(&sealed) = "ERABReleaseItemBearerRelCompIEContainer"
		*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABReleaseItemBearerRelCompIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABReleaseItemBearerRelCompIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseItemBearerRelCompIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEContainer")
			}
			return fields, nil
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(&sealed) = func(fields s19.ERABReleaseItemBearerRelCompIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s19.BridgeERABReleaseItemBearerRelCompIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldCapture(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEContainer, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldCompare(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABSetupItemBearerSUResIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResIEValueIETableCodec(table s00.ERABSetupItemBearerSUResIEValueIETable, bounds aper.ListBounds) s19.ERABSetupItemBearerSUResIEContainerValueCodec {
	if !*s00.BridgeERABSetupItemBearerSUResIEValueIETableFieldBound(&table) {
		return s19.ERABSetupItemBearerSUResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABSetupItemBearerSUResIEContainerValueCodec {
		sealed := s19.ERABSetupItemBearerSUResIEContainerValueCodec{}
		*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldPath(&sealed) = "ERABSetupItemBearerSUResIEContainer"
		*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABSetupItemBearerSUResIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABSetupItemBearerSUResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemBearerSUResIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEContainer")
			}
			return fields, nil
		}
		*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(&sealed) = func(fields s19.ERABSetupItemBearerSUResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s19.BridgeERABSetupItemBearerSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemBearerSUResIEContainer, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemBearerSUResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABSetupItemCtxtSUResIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResIEValueIETableCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable, bounds aper.ListBounds) s19.ERABSetupItemCtxtSUResIEContainerValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResIEValueIETableFieldBound(&table) {
		return s19.ERABSetupItemCtxtSUResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABSetupItemCtxtSUResIEContainerValueCodec {
		sealed := s19.ERABSetupItemCtxtSUResIEContainerValueCodec{}
		*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldPath(&sealed) = "ERABSetupItemCtxtSUResIEContainer"
		*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABSetupItemCtxtSUResIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABSetupItemCtxtSUResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemCtxtSUResIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEContainer")
			}
			return fields, nil
		}
		*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&sealed) = func(fields s19.ERABSetupItemCtxtSUResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s19.BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEContainer, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndIEValueIETableCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s20.ERABToBeModifiedItemBearerModIndIEContainerValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModIndIEValueIETableFieldBound(&table) {
		return s20.ERABToBeModifiedItemBearerModIndIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABToBeModifiedItemBearerModIndIEContainerValueCodec {
		sealed := s20.ERABToBeModifiedItemBearerModIndIEContainerValueCodec{}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldPath(&sealed) = "ERABToBeModifiedItemBearerModIndIEContainer"
		*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABToBeModifiedItemBearerModIndIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABToBeModifiedItemBearerModIndIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModIndIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEContainer")
			}
			return fields, nil
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&sealed) = func(fields s20.ERABToBeModifiedItemBearerModIndIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s20.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEContainer, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return ERABToBeModifiedItemBearerModReqIEContainerValueCodec{path: "ERABToBeModifiedItemBearerModReqIEContainer", decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeModifiedItemBearerModReqIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeModifiedItemBearerModReqIEField
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
			return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModReqIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ERABToBeModifiedItemBearerModReqIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ERABToBeSwitchedULItemIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABToBeSwitchedULItemIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemIEValueIETableCodec(table s00.ERABToBeSwitchedULItemIEValueIETable, bounds aper.ListBounds) s20.ERABToBeSwitchedULItemIEContainerValueCodec {
	if !*s00.BridgeERABToBeSwitchedULItemIEValueIETableFieldBound(&table) {
		return s20.ERABToBeSwitchedULItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABToBeSwitchedULItemIEContainerValueCodec {
		sealed := s20.ERABToBeSwitchedULItemIEContainerValueCodec{}
		*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULItemIEContainer"
		*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABToBeSwitchedULItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABToBeSwitchedULItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULItemIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEContainer")
			}
			return fields, nil
		}
		*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s20.ERABToBeSwitchedULItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s20.BridgeERABToBeSwitchedULItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeSwitchedULItemIEContainer, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeSwitchedULItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABUsageReportItemIEs}} codec of TS 36.413.
func ERABUsageReportItemIEValueIETableCodec(table s00.ERABUsageReportItemIEValueIETable, bounds aper.ListBounds) s20.ERABUsageReportItemIEContainerValueCodec {
	if !*s00.BridgeERABUsageReportItemIEValueIETableFieldBound(&table) {
		return s20.ERABUsageReportItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABUsageReportItemIEContainerValueCodec {
		sealed := s20.ERABUsageReportItemIEContainerValueCodec{}
		*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldPath(&sealed) = "ERABUsageReportItemIEContainer"
		*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABUsageReportItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABUsageReportItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABUsageReportItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABUsageReportItemIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemIEContainer")
			}
			return fields, nil
		}
		*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s20.ERABUsageReportItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s20.BridgeERABUsageReportItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldCapture(&sealed) = func(v s20.ERABUsageReportItemIEContainer, options aper.DecodeState) (s20.ERABUsageReportItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldCompare(&sealed) = func(v s20.ERABUsageReportItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverCancelAcknowledgeIEs}} codec of TS 36.413.
func HandoverCancelAcknowledgeIEValueIETableCodec(table s00.HandoverCancelAcknowledgeIEValueIETable, bounds aper.ListBounds) s26.HandoverCancelAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeHandoverCancelAcknowledgeIEValueIETableFieldBound(&table) {
		return s26.HandoverCancelAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverCancelAcknowledgeIEContainerValueCodec {
		sealed := s26.HandoverCancelAcknowledgeIEContainerValueCodec{}
		*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldPath(&sealed) = "HandoverCancelAcknowledgeIEContainer"
		*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverCancelAcknowledgeIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverCancelAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelAcknowledgeIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEContainer")
			}
			return fields, nil
		}
		*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(&sealed) = func(fields s26.HandoverCancelAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldCapture(&sealed) = func(v s26.HandoverCancelAcknowledgeIEContainer, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldCompare(&sealed) = func(v s26.HandoverCancelAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverCancelIEs}} codec of TS 36.413.
func HandoverCancelIEValueIETableCodec(table s00.HandoverCancelIEValueIETable, bounds aper.ListBounds) s21.HandoverCancelIEContainerValueCodec {
	if !*s00.BridgeHandoverCancelIEValueIETableFieldBound(&table) {
		return s21.HandoverCancelIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s21.HandoverCancelIEContainerValueCodec {
		sealed := s21.HandoverCancelIEContainerValueCodec{}
		*s21.BridgeHandoverCancelIEContainerValueCodecFieldPath(&sealed) = "HandoverCancelIEContainer"
		*s21.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.HandoverCancelIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.HandoverCancelIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.HandoverCancelIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverCancelIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverCancelIEContainer")
			}
			return fields, nil
		}
		*s21.BridgeHandoverCancelIEContainerValueCodecFieldEncode(&sealed) = func(fields s21.HandoverCancelIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s21.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s21.BridgeHandoverCancelIEContainerValueCodecFieldCapture(&sealed) = func(v s21.HandoverCancelIEContainer, options aper.DecodeState) (s21.HandoverCancelIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s21.BridgeHandoverCancelIEContainerValueCodecFieldCompare(&sealed) = func(v s21.HandoverCancelIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeHandoverCancelIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverFailureIEs}} codec of TS 36.413.
func HandoverFailureIEValueIETableCodec(table s00.HandoverFailureIEValueIETable, bounds aper.ListBounds) s26.HandoverFailureIEContainerValueCodec {
	if !*s00.BridgeHandoverFailureIEValueIETableFieldBound(&table) {
		return s26.HandoverFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverFailureIEContainerValueCodec {
		sealed := s26.HandoverFailureIEContainerValueCodec{}
		*s26.BridgeHandoverFailureIEContainerValueCodecFieldPath(&sealed) = "HandoverFailureIEContainer"
		*s26.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverFailureIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverFailureIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverFailureIEContainer")
			}
			return fields, nil
		}
		*s26.BridgeHandoverFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s26.HandoverFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s26.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s26.BridgeHandoverFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s26.HandoverFailureIEContainer, options aper.DecodeState) (s26.HandoverFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeHandoverFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s26.HandoverFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverPreparationFailureIEs}} codec of TS 36.413.
func HandoverPreparationFailureIEValueIETableCodec(table s00.HandoverPreparationFailureIEValueIETable, bounds aper.ListBounds) s26.HandoverPreparationFailureIEContainerValueCodec {
	if !*s00.BridgeHandoverPreparationFailureIEValueIETableFieldBound(&table) {
		return s26.HandoverPreparationFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverPreparationFailureIEContainerValueCodec {
		sealed := s26.HandoverPreparationFailureIEContainerValueCodec{}
		*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldPath(&sealed) = "HandoverPreparationFailureIEContainer"
		*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverPreparationFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverPreparationFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverPreparationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverPreparationFailureIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEContainer")
			}
			return fields, nil
		}
		*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s26.HandoverPreparationFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s26.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s26.HandoverPreparationFailureIEContainer, options aper.DecodeState) (s26.HandoverPreparationFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s26.HandoverPreparationFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABDataForwardingItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABDataForwardingItemIEs}} codec of TS 36.413.
func ERABDataForwardingItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABDataForwardingItemIEValueIETable) s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABDataForwardingItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s18.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABDataForwardingItemIEValueProtocolErrorIEContainerList"
		*s18.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABDataForwardingItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABDataForwardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABDataForwardingItemIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(&codec))(s18.ERABDataForwardingItemIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABFailedToResumeItemResumeReqIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable) s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList"
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedToResumeItemResumeReqIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedToResumeItemResumeReqIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABFailedToResumeItemResumeResIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable) s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList"
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedToResumeItemResumeResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedToResumeItemResumeResIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABFailedtoSetupItemHOReqAckIEs}} codec of TS 36.413.
func ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable) s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABFailedtoSetupItemHOReqAckIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList"
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedtoSetupItemHOReqAckIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedtoSetupItemHOReqAckIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABItemIEs}} codec of TS 36.413.
func ERABItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABItemIEValueIETable) s19.ERABItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.ERABItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABItemIEValueProtocolErrorIEContainerList"
		*s19.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABItemIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABItemIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABItemIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABItemIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABItemIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABItemIEContainerValueCodecFieldEncode(&codec))(s19.ERABItemIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.ERABItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABModifyItemBearerModConfIEs}} codec of TS 36.413.
func ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListCodec(table s00.ERABModifyItemBearerModConfIEValueIETable) s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABModifyItemBearerModConfIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList"
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABModifyItemBearerModConfIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(&codec))(s19.ERABModifyItemBearerModConfIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABModifyItemBearerModResIEs}} codec of TS 36.413.
func ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListCodec(table s00.ERABModifyItemBearerModResIEValueIETable) s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABModifyItemBearerModResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList"
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABModifyItemBearerModResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(&codec))(s19.ERABModifyItemBearerModResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABNotToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable) s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList"
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABNotToBeModifiedItemBearerModIndIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s19.ERABNotToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABReleaseItemBearerRelCompIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable) s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABReleaseItemBearerRelCompIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList"
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABReleaseItemBearerRelCompIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(&codec))(s19.ERABReleaseItemBearerRelCompIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABSetupItemBearerSUResIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListCodec(table s00.ERABSetupItemBearerSUResIEValueIETable) s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSetupItemBearerSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList"
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABSetupItemBearerSUResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(&codec))(s19.ERABSetupItemBearerSUResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABSetupItemCtxtSUResIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList"
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABSetupItemCtxtSUResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s19.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABToBeModifiedItemBearerModIndIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable) s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModIndIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec{}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList"
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABToBeModifiedItemBearerModIndIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s20.ERABToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListValueCodec{path: "ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeModifiedItemBearerModReqIEField
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
			return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
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
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolErrorIEContainerList(
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

// ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABToBeSwitchedULItemIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeSwitchedULItemIEValueIETable) s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeSwitchedULItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList"
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABToBeSwitchedULItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(&codec))(s20.ERABToBeSwitchedULItemIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABUsageReportItemIEs}} codec of TS 36.413.
func ERABUsageReportItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABUsageReportItemIEValueIETable) s20.ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABUsageReportItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s20.ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s20.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABUsageReportItemIEValueProtocolErrorIEContainerList"
		*s20.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABUsageReportItemIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABUsageReportItemIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABUsageReportItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABUsageReportItemIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABUsageReportItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(&codec))(s20.ERABUsageReportItemIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABUsageReportItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s20.ERABUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABUsageReportItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverCancelAcknowledgeIEs}} codec of TS 36.413.
func HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.HandoverCancelAcknowledgeIEValueIETable) s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverCancelAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList"
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverCancelAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.HandoverCancelAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverCancelIEs}} codec of TS 36.413.
func HandoverCancelIEValueProtocolErrorIEContainerListCodec(table s00.HandoverCancelIEValueIETable) s21.HandoverCancelIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverCancelIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.HandoverCancelIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s21.HandoverCancelIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s21.HandoverCancelIEValueProtocolErrorIEContainerListValueCodec{}
		*s21.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "HandoverCancelIEValueProtocolErrorIEContainerList"
		*s21.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.HandoverCancelIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.HandoverCancelIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.HandoverCancelIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverCancelIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverCancelIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s21.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.HandoverCancelIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeHandoverCancelIEContainerValueCodecFieldEncode(&codec))(s21.HandoverCancelIEContainer(value), fresh, budget)
		}
		*s21.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.HandoverCancelIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s21.HandoverCancelIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.HandoverCancelIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCancelIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverFailureIEs}} codec of TS 36.413.
func HandoverFailureIEValueProtocolErrorIEContainerListCodec(table s00.HandoverFailureIEValueIETable) s26.HandoverFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s26.HandoverFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s26.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "HandoverFailureIEValueProtocolErrorIEContainerList"
		*s26.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverFailureIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverFailureIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverFailureIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverFailureIEContainerValueCodecFieldEncode(&codec))(s26.HandoverFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s26.HandoverFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverPreparationFailureIEs}} codec of TS 36.413.
func HandoverPreparationFailureIEValueProtocolErrorIEContainerListCodec(table s00.HandoverPreparationFailureIEValueIETable) s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverPreparationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "HandoverPreparationFailureIEValueProtocolErrorIEContainerList"
		*s26.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverPreparationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverPreparationFailureIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(&codec))(s26.HandoverPreparationFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABAdmittedItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABAdmittedItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABAdmittedItemIEValueProtocolIEContainerListCodec(table s00.ERABAdmittedItemIEValueIETable, bounds aper.ListBounds) s18.ERABAdmittedItemIEValueProtocolIEContainerListValueCodec {
	codec := s28.ERABAdmittedItemIEValueIETableCodec(table, bounds)
	if *s18.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABAdmittedItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABAdmittedItemIEValueProtocolIEContainerListValueCodec {
		sealed := s18.ERABAdmittedItemIEValueProtocolIEContainerListValueCodec{}
		*s18.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABAdmittedItemIEValueProtocolIEContainerList"
		*s18.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABAdmittedItemIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABAdmittedItemIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABAdmittedItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABAdmittedItemIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABAdmittedItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(&codec))(s18.ERABAdmittedItemIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABAdmittedItemIEValueProtocolIEContainerList, options aper.DecodeState) (s18.ERABAdmittedItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABAdmittedItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s28.BridgeERABAdmittedItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABDataForwardingItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABDataForwardingItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABDataForwardingItemIEValueProtocolIEContainerListCodec(table s00.ERABDataForwardingItemIEValueIETable, bounds aper.ListBounds) s18.ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABDataForwardingItemIEValueIETableCodec(table, bounds)
	if *s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec {
		sealed := s18.ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec{}
		*s18.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABDataForwardingItemIEValueProtocolIEContainerList"
		*s18.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABDataForwardingItemIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABDataForwardingItemIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABDataForwardingItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABDataForwardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABDataForwardingItemIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABDataForwardingItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(&codec))(s18.ERABDataForwardingItemIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABDataForwardingItemIEValueProtocolIEContainerList, options aper.DecodeState) (s18.ERABDataForwardingItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABDataForwardingItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABFailedToResumeItemResumeReqIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable, bounds aper.ListBounds) s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeReqIEValueIETableCodec(table, bounds)
	if *s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList"
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedToResumeItemResumeReqIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedToResumeItemResumeReqIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABFailedToResumeItemResumeResIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable, bounds aper.ListBounds) s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeResIEValueIETableCodec(table, bounds)
	if *s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodec {
		sealed := s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodec{}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList"
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedToResumeItemResumeResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedToResumeItemResumeResIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, options aper.DecodeState) (s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABFailedtoSetupItemHOReqAckIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable, bounds aper.ListBounds) s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec {
	codec := ERABFailedtoSetupItemHOReqAckIEValueIETableCodec(table, bounds)
	if *s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec {
		sealed := s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList"
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABFailedtoSetupItemHOReqAckIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(&codec))(s18.ERABFailedtoSetupItemHOReqAckIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, options aper.DecodeState) (s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABItemIEValueProtocolIEContainerListCodec(table s00.ERABItemIEValueIETable, bounds aper.ListBounds) s19.ERABItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABItemIEValueIETableCodec(table, bounds)
	if *s19.BridgeERABItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABItemIEValueProtocolIEContainerListValueCodec {
		sealed := s19.ERABItemIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABItemIEValueProtocolIEContainerList"
		*s19.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABItemIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABItemIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABItemIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABItemIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABItemIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABItemIEContainerValueCodecFieldEncode(&codec))(s19.ERABItemIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABItemIEValueProtocolIEContainerList, options aper.DecodeState) (s19.ERABItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModConfIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABModifyItemBearerModConfIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABModifyItemBearerModConfIEValueProtocolIEContainerListCodec(table s00.ERABModifyItemBearerModConfIEValueIETable, bounds aper.ListBounds) s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec {
	codec := ERABModifyItemBearerModConfIEValueIETableCodec(table, bounds)
	if *s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec {
		sealed := s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModConfIEValueProtocolIEContainerList"
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABModifyItemBearerModConfIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModConfIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(&codec))(s19.ERABModifyItemBearerModConfIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, options aper.DecodeState) (s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModResIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABModifyItemBearerModResIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABModifyItemBearerModResIEValueProtocolIEContainerListCodec(table s00.ERABModifyItemBearerModResIEValueIETable, bounds aper.ListBounds) s19.ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec {
	codec := ERABModifyItemBearerModResIEValueIETableCodec(table, bounds)
	if *s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec {
		sealed := s19.ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModResIEValueProtocolIEContainerList"
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABModifyItemBearerModResIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABModifyItemBearerModResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModResIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABModifyItemBearerModResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(&codec))(s19.ERABModifyItemBearerModResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyItemBearerModResIEValueProtocolIEContainerList, options aper.DecodeState) (s19.ERABModifyItemBearerModResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyItemBearerModResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABNotToBeModifiedItemBearerModIndIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
	codec := ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table, bounds)
	if *s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
		sealed := s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList"
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABNotToBeModifiedItemBearerModIndIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s19.ERABNotToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, options aper.DecodeState) (s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABReleaseItemBearerRelCompIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListCodec(table s00.ERABReleaseItemBearerRelCompIEValueIETable, bounds aper.ListBounds) s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec {
	codec := ERABReleaseItemBearerRelCompIEValueIETableCodec(table, bounds)
	if *s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec {
		sealed := s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList"
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABReleaseItemBearerRelCompIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(&codec))(s19.ERABReleaseItemBearerRelCompIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, options aper.DecodeState) (s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABSetupItemBearerSUResIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABSetupItemBearerSUResIEValueProtocolIEContainerListCodec(table s00.ERABSetupItemBearerSUResIEValueIETable, bounds aper.ListBounds) s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec {
	codec := ERABSetupItemBearerSUResIEValueIETableCodec(table, bounds)
	if *s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec {
		sealed := s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupItemBearerSUResIEValueProtocolIEContainerList"
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABSetupItemBearerSUResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemBearerSUResIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(&codec))(s19.ERABSetupItemBearerSUResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, options aper.DecodeState) (s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABSetupItemCtxtSUResIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABSetupItemCtxtSUResIEValueProtocolIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable, bounds aper.ListBounds) s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, bounds)
	if *s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec {
		sealed := s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupItemCtxtSUResIEValueProtocolIEContainerList"
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.ERABSetupItemCtxtSUResIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemCtxtSUResIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s19.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, options aper.DecodeState) (s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeModifiedItemBearerModIndIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec(table s00.ERABToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeModifiedItemBearerModIndIEValueIETableCodec(table, bounds)
	if *s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
		sealed := s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec{}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList"
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABToBeModifiedItemBearerModIndIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s20.ERABToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, options aper.DecodeState) (s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListValueCodec{path: "ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeModifiedItemBearerModReqIEField
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
			return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeModifiedItemBearerModReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, options aper.DecodeState) (ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeERABToBeModifiedItemBearerModReqIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// ERABToBeSwitchedULItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeSwitchedULItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABToBeSwitchedULItemIEValueProtocolIEContainerListCodec(table s00.ERABToBeSwitchedULItemIEValueIETable, bounds aper.ListBounds) s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeSwitchedULItemIEValueIETableCodec(table, bounds)
	if *s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec {
		sealed := s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec{}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULItemIEValueProtocolIEContainerList"
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABToBeSwitchedULItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULItemIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(&codec))(s20.ERABToBeSwitchedULItemIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, options aper.DecodeState) (s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABUsageReportItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABUsageReportItemIEValueProtocolIEContainerListCodec(table s00.ERABUsageReportItemIEValueIETable, bounds aper.ListBounds) s20.ERABUsageReportItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABUsageReportItemIEValueIETableCodec(table, bounds)
	if *s20.BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.ERABUsageReportItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s20.ERABUsageReportItemIEValueProtocolIEContainerListValueCodec {
		sealed := s20.ERABUsageReportItemIEValueProtocolIEContainerListValueCodec{}
		*s20.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABUsageReportItemIEValueProtocolIEContainerList"
		*s20.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABUsageReportItemIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.ERABUsageReportItemIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.ERABUsageReportItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABUsageReportItemIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.ERABUsageReportItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(&codec))(s20.ERABUsageReportItemIEContainer(value), fresh, budget)
		}
		*s20.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.ERABUsageReportItemIEValueProtocolIEContainerList, options aper.DecodeState) (s20.ERABUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.ERABUsageReportItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABUsageReportItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverCancelAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverCancelAcknowledgeIEValueProtocolIEContainerListCodec(table s00.HandoverCancelAcknowledgeIEValueIETable, bounds aper.ListBounds) s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := HandoverCancelAcknowledgeIEValueIETableCodec(table, bounds)
	if *s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec {
		sealed := s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec{}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "HandoverCancelAcknowledgeIEValueProtocolIEContainerList"
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverCancelAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelAcknowledgeIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverCancelAcknowledgeIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.HandoverCancelAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverCancelIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverCancelIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverCancelIEValueProtocolIEContainerListCodec(table s00.HandoverCancelIEValueIETable, bounds aper.ListBounds) s21.HandoverCancelIEValueProtocolIEContainerListValueCodec {
	codec := HandoverCancelIEValueIETableCodec(table, bounds)
	if *s21.BridgeHandoverCancelIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.HandoverCancelIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s21.HandoverCancelIEValueProtocolIEContainerListValueCodec {
		sealed := s21.HandoverCancelIEValueProtocolIEContainerListValueCodec{}
		*s21.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "HandoverCancelIEValueProtocolIEContainerList"
		*s21.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.HandoverCancelIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.HandoverCancelIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.HandoverCancelIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverCancelIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverCancelIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverCancelIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s21.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.HandoverCancelIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeHandoverCancelIEContainerValueCodecFieldEncode(&codec))(s21.HandoverCancelIEContainer(value), fresh, budget)
		}
		*s21.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.HandoverCancelIEValueProtocolIEContainerList, options aper.DecodeState) (s21.HandoverCancelIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s21.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.HandoverCancelIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeHandoverCancelIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverFailureIEValueProtocolIEContainerListCodec(table s00.HandoverFailureIEValueIETable, bounds aper.ListBounds) s26.HandoverFailureIEValueProtocolIEContainerListValueCodec {
	codec := HandoverFailureIEValueIETableCodec(table, bounds)
	if *s26.BridgeHandoverFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s26.HandoverFailureIEValueProtocolIEContainerListValueCodec{}
		*s26.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "HandoverFailureIEValueProtocolIEContainerList"
		*s26.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverFailureIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverFailureIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverFailureIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverFailureIEContainerValueCodecFieldEncode(&codec))(s26.HandoverFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s26.HandoverFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeHandoverFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverPreparationFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverPreparationFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverPreparationFailureIEValueProtocolIEContainerListCodec(table s00.HandoverPreparationFailureIEValueIETable, bounds aper.ListBounds) s26.HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec {
	codec := HandoverPreparationFailureIEValueIETableCodec(table, bounds)
	if *s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s26.HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s26.HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec{}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "HandoverPreparationFailureIEValueProtocolIEContainerList"
		*s26.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.HandoverPreparationFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.HandoverPreparationFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.HandoverPreparationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverPreparationFailureIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverPreparationFailureIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.HandoverPreparationFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(&codec))(s26.HandoverPreparationFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.HandoverPreparationFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s26.HandoverPreparationFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.HandoverPreparationFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eRABAdmittedItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABAdmittedItemIEValue].
type ERABAdmittedItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s18.ERABAdmittedItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s18.ERABAdmittedItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABFailedToResumeItemResumeReqIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedToResumeItemResumeReqIEValue].
type ERABFailedToResumeItemResumeReqIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s18.ERABFailedToResumeItemResumeReqIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s18.ERABFailedToResumeItemResumeReqIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEField(v *s18.ERABFailedToResumeItemResumeReqIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s18.BridgeERABFailedToResumeItemResumeReqIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s18.BridgeERABFailedToResumeItemResumeReqIEFieldFieldReplay(v), *s18.BridgeERABFailedToResumeItemResumeReqIEFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEField(v *s18.ERABFailedToResumeItemResumeReqIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s18.BridgeERABFailedToResumeItemResumeReqIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s18.BridgeERABFailedToResumeItemResumeReqIEFieldFieldReplay(v), *s18.BridgeERABFailedToResumeItemResumeReqIEFieldFieldWithoutReplay(v))
}

// eRABFailedToResumeItemResumeResIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedToResumeItemResumeResIEValue].
type ERABFailedToResumeItemResumeResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s18.ERABFailedToResumeItemResumeResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s18.ERABFailedToResumeItemResumeResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEField(v *s18.ERABFailedToResumeItemResumeResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s18.BridgeERABFailedToResumeItemResumeResIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s18.BridgeERABFailedToResumeItemResumeResIEFieldFieldReplay(v), *s18.BridgeERABFailedToResumeItemResumeResIEFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEField(v *s18.ERABFailedToResumeItemResumeResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s18.BridgeERABFailedToResumeItemResumeResIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s18.BridgeERABFailedToResumeItemResumeResIEFieldFieldReplay(v), *s18.BridgeERABFailedToResumeItemResumeResIEFieldFieldWithoutReplay(v))
}

// eRABFailedtoSetupItemHOReqAckIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s18.ERABFailedtoSetupItemHOReqAckIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s18.ERABFailedtoSetupItemHOReqAckIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEField(v *s18.ERABFailedtoSetupItemHOReqAckIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s18.BridgeERABFailedtoSetupItemHOReqAckIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldReplay(v), *s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldWithoutReplay(v))
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEField(v *s18.ERABFailedtoSetupItemHOReqAckIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s18.BridgeERABFailedtoSetupItemHOReqAckIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldReplay(v), *s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldWithoutReplay(v))
}

// eRABItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABItemIEValue].
type ERABItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.ERABItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.ERABItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABItemIEValueCaptureS1APProtocolIEField(v *s19.ERABItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s19.BridgeERABItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s19.BridgeERABItemIEFieldFieldReplay(v), *s19.BridgeERABItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABItemIEValueCompareS1APProtocolIEField(v *s19.ERABItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s19.BridgeERABItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s19.BridgeERABItemIEFieldFieldReplay(v), *s19.BridgeERABItemIEFieldFieldWithoutReplay(v))
}

// eRABModifyItemBearerModConfIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.ERABModifyItemBearerModConfIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.ERABModifyItemBearerModConfIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEField(v *s19.ERABModifyItemBearerModConfIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s19.BridgeERABModifyItemBearerModConfIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s19.BridgeERABModifyItemBearerModConfIEFieldFieldReplay(v), *s19.BridgeERABModifyItemBearerModConfIEFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEField(v *s19.ERABModifyItemBearerModConfIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s19.BridgeERABModifyItemBearerModConfIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s19.BridgeERABModifyItemBearerModConfIEFieldFieldReplay(v), *s19.BridgeERABModifyItemBearerModConfIEFieldFieldWithoutReplay(v))
}

// eRABModifyItemBearerModResIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.ERABModifyItemBearerModResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.ERABModifyItemBearerModResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEField(v *s19.ERABModifyItemBearerModResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s19.BridgeERABModifyItemBearerModResIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s19.BridgeERABModifyItemBearerModResIEFieldFieldReplay(v), *s19.BridgeERABModifyItemBearerModResIEFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEField(v *s19.ERABModifyItemBearerModResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s19.BridgeERABModifyItemBearerModResIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s19.BridgeERABModifyItemBearerModResIEFieldFieldReplay(v), *s19.BridgeERABModifyItemBearerModResIEFieldFieldWithoutReplay(v))
}

// eRABNotToBeModifiedItemBearerModIndIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.ERABNotToBeModifiedItemBearerModIndIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.ERABNotToBeModifiedItemBearerModIndIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(v *s19.ERABNotToBeModifiedItemBearerModIndIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldReplay(v), *s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v))
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(v *s19.ERABNotToBeModifiedItemBearerModIndIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldReplay(v), *s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v))
}

// eRABReleaseItemBearerRelCompIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.ERABReleaseItemBearerRelCompIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.ERABReleaseItemBearerRelCompIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEField(v *s19.ERABReleaseItemBearerRelCompIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s19.BridgeERABReleaseItemBearerRelCompIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s19.BridgeERABReleaseItemBearerRelCompIEFieldFieldReplay(v), *s19.BridgeERABReleaseItemBearerRelCompIEFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEField(v *s19.ERABReleaseItemBearerRelCompIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s19.BridgeERABReleaseItemBearerRelCompIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s19.BridgeERABReleaseItemBearerRelCompIEFieldFieldReplay(v), *s19.BridgeERABReleaseItemBearerRelCompIEFieldFieldWithoutReplay(v))
}

// eRABSetupItemBearerSUResIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.ERABSetupItemBearerSUResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.ERABSetupItemBearerSUResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEField(v *s19.ERABSetupItemBearerSUResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s19.BridgeERABSetupItemBearerSUResIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s19.BridgeERABSetupItemBearerSUResIEFieldFieldReplay(v), *s19.BridgeERABSetupItemBearerSUResIEFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEField(v *s19.ERABSetupItemBearerSUResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s19.BridgeERABSetupItemBearerSUResIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s19.BridgeERABSetupItemBearerSUResIEFieldFieldReplay(v), *s19.BridgeERABSetupItemBearerSUResIEFieldFieldWithoutReplay(v))
}

// eRABSetupItemCtxtSUResIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.ERABSetupItemCtxtSUResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.ERABSetupItemCtxtSUResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEField(v *s19.ERABSetupItemCtxtSUResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s19.BridgeERABSetupItemCtxtSUResIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s19.BridgeERABSetupItemCtxtSUResIEFieldFieldReplay(v), *s19.BridgeERABSetupItemCtxtSUResIEFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(v *s19.ERABSetupItemCtxtSUResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s19.BridgeERABSetupItemCtxtSUResIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s19.BridgeERABSetupItemCtxtSUResIEFieldFieldReplay(v), *s19.BridgeERABSetupItemCtxtSUResIEFieldFieldWithoutReplay(v))
}

// eRABDataForwardingItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABDataForwardingItemIEValue].
type ERABDataForwardingItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s18.ERABDataForwardingItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s18.ERABDataForwardingItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEField(v *s18.ERABDataForwardingItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s18.BridgeERABDataForwardingItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s18.BridgeERABDataForwardingItemIEFieldFieldReplay(v), *s18.BridgeERABDataForwardingItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEField(v *s18.ERABDataForwardingItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s18.BridgeERABDataForwardingItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s18.BridgeERABDataForwardingItemIEFieldFieldReplay(v), *s18.BridgeERABDataForwardingItemIEFieldFieldWithoutReplay(v))
}

// eRABToBeModifyItemBearerModReqExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeModifyItemBearerModReqExtIEsValue].
type ERABToBeModifyItemBearerModReqExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s24.ERABToBeModifyItemBearerModReqExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s24.ERABToBeModifyItemBearerModReqExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeModifyItemBearerModReqExtIEsValueCaptureS1APProtocolExtensionField(v *s24.ERABToBeModifyItemBearerModReqExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s24.BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldReplay(v), *s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueCompareS1APProtocolExtensionField(v *s24.ERABToBeModifyItemBearerModReqExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s24.BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldReplay(v), *s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldWithoutReplay(v))
}

// eRABToBeModifiedItemBearerModIndIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeModifiedItemBearerModIndIEValue].
type ERABToBeModifiedItemBearerModIndIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s20.ERABToBeModifiedItemBearerModIndIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s20.ERABToBeModifiedItemBearerModIndIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(v *s20.ERABToBeModifiedItemBearerModIndIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s20.BridgeERABToBeModifiedItemBearerModIndIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s20.BridgeERABToBeModifiedItemBearerModIndIEFieldFieldReplay(v), *s20.BridgeERABToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v))
}
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(v *s20.ERABToBeModifiedItemBearerModIndIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s20.BridgeERABToBeModifiedItemBearerModIndIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s20.BridgeERABToBeModifiedItemBearerModIndIEFieldFieldReplay(v), *s20.BridgeERABToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v))
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABToBeSwitchedULItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSwitchedULItemIEValue].
type ERABToBeSwitchedULItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s20.ERABToBeSwitchedULItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s20.ERABToBeSwitchedULItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEField(v *s20.ERABToBeSwitchedULItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s20.BridgeERABToBeSwitchedULItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s20.BridgeERABToBeSwitchedULItemIEFieldFieldReplay(v), *s20.BridgeERABToBeSwitchedULItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEField(v *s20.ERABToBeSwitchedULItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s20.BridgeERABToBeSwitchedULItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s20.BridgeERABToBeSwitchedULItemIEFieldFieldReplay(v), *s20.BridgeERABToBeSwitchedULItemIEFieldFieldWithoutReplay(v))
}

// eRABUsageReportItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABUsageReportItemIEValue].
type ERABUsageReportItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s20.ERABUsageReportItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s20.ERABUsageReportItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEField(v *s20.ERABUsageReportItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s20.BridgeERABUsageReportItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s20.BridgeERABUsageReportItemIEFieldFieldReplay(v), *s20.BridgeERABUsageReportItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABUsageReportItemIEValueCompareS1APProtocolIEField(v *s20.ERABUsageReportItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s20.BridgeERABUsageReportItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s20.BridgeERABUsageReportItemIEFieldFieldReplay(v), *s20.BridgeERABUsageReportItemIEFieldFieldWithoutReplay(v))
}

// handoverCancelIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverCancelIEValue].
type HandoverCancelIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s21.HandoverCancelIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s21.HandoverCancelIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverCancelIEValueCaptureS1APProtocolIEField(v *s21.HandoverCancelIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s21.BridgeHandoverCancelIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s21.BridgeHandoverCancelIEFieldFieldReplay(v), *s21.BridgeHandoverCancelIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverCancelIEValueCompareS1APProtocolIEField(v *s21.HandoverCancelIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s21.BridgeHandoverCancelIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s21.BridgeHandoverCancelIEFieldFieldReplay(v), *s21.BridgeHandoverCancelIEFieldFieldWithoutReplay(v))
}

// handoverCancelAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s26.HandoverCancelAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s26.HandoverCancelAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEField(v *s26.HandoverCancelAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s26.BridgeHandoverCancelAcknowledgeIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s26.BridgeHandoverCancelAcknowledgeIEFieldFieldReplay(v), *s26.BridgeHandoverCancelAcknowledgeIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEField(v *s26.HandoverCancelAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s26.BridgeHandoverCancelAcknowledgeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s26.BridgeHandoverCancelAcknowledgeIEFieldFieldReplay(v), *s26.BridgeHandoverCancelAcknowledgeIEFieldFieldWithoutReplay(v))
}

// handoverFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverFailureIEValue].
type HandoverFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s26.HandoverFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s26.HandoverFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverFailureIEValueCaptureS1APProtocolIEField(v *s26.HandoverFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s26.BridgeHandoverFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s26.BridgeHandoverFailureIEFieldFieldReplay(v), *s26.BridgeHandoverFailureIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverFailureIEValueCompareS1APProtocolIEField(v *s26.HandoverFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s26.BridgeHandoverFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s26.BridgeHandoverFailureIEFieldFieldReplay(v), *s26.BridgeHandoverFailureIEFieldFieldWithoutReplay(v))
}

// handoverPreparationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverPreparationFailureIEValue].
type HandoverPreparationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s26.HandoverPreparationFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s26.HandoverPreparationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEField(v *s26.HandoverPreparationFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s26.BridgeHandoverPreparationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s26.BridgeHandoverPreparationFailureIEFieldFieldReplay(v), *s26.BridgeHandoverPreparationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEField(v *s26.HandoverPreparationFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s26.BridgeHandoverPreparationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s26.BridgeHandoverPreparationFailureIEFieldFieldReplay(v), *s26.BridgeHandoverPreparationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEField(v *s26.InitialContextSetupFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s26.BridgeInitialContextSetupFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s26.BridgeInitialContextSetupFailureIEFieldFieldReplay(v), *s26.BridgeInitialContextSetupFailureIEFieldFieldWithoutReplay(v))
}
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEField(v *s26.InitialContextSetupFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s26.BridgeInitialContextSetupFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s26.BridgeInitialContextSetupFailureIEFieldFieldReplay(v), *s26.BridgeInitialContextSetupFailureIEFieldFieldWithoutReplay(v))
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
func BridgeERABDataForwardingItemIEValueCaptureS1APERABIEContainerList(v *s18.ERABDataForwardingItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABDataForwardingItemIEValueCompareS1APERABIEContainerList(v *s18.ERABDataForwardingItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APERABIEContainerList(v *s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APERABIEContainerList(v *s18.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APERABIEContainerList(v *s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APERABIEContainerList(v *s18.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APERABIEContainerList(v *s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APERABIEContainerList(v *s18.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABItemIEValueCaptureS1APERABIEContainerList(v *s19.ERABItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABItemIEValueCompareS1APERABIEContainerList(v *s19.ERABItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APERABIEContainerList(v *s19.ERABModifyItemBearerModConfIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModConfIEValueCompareS1APERABIEContainerList(v *s19.ERABModifyItemBearerModConfIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModResIEValueCaptureS1APERABIEContainerList(v *s19.ERABModifyItemBearerModResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModResIEValueCompareS1APERABIEContainerList(v *s19.ERABModifyItemBearerModResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APERABIEContainerList(v *s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APERABIEContainerList(v *s19.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APERABIEContainerList(v *s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APERABIEContainerList(v *s19.ERABReleaseItemBearerRelCompIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APERABIEContainerList(v *s19.ERABSetupItemBearerSUResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResIEValueCompareS1APERABIEContainerList(v *s19.ERABSetupItemBearerSUResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APERABIEContainerList(v *s19.ERABSetupItemCtxtSUResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APERABIEContainerList(v *s19.ERABSetupItemCtxtSUResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APERABIEContainerList(v *s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APERABIEContainerList(v *s20.ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APERABIEContainerList(v *s20.ERABToBeSwitchedULItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemIEValueCompareS1APERABIEContainerList(v *s20.ERABToBeSwitchedULItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemIEValueCaptureS1APERABIEContainerList(v *s20.ERABUsageReportItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemIEValueCompareS1APERABIEContainerList(v *s20.ERABUsageReportItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APERABIEContainerList(v *s26.HandoverCancelAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APERABIEContainerList(v *s26.HandoverCancelAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelIEValueCaptureS1APERABIEContainerList(v *s21.HandoverCancelIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelIEValueCompareS1APERABIEContainerList(v *s21.HandoverCancelIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverFailureIEValueCaptureS1APERABIEContainerList(v *s26.HandoverFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverFailureIEValueCompareS1APERABIEContainerList(v *s26.HandoverFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverPreparationFailureIEValueCaptureS1APERABIEContainerList(v *s26.HandoverPreparationFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverPreparationFailureIEValueCompareS1APERABIEContainerList(v *s26.HandoverPreparationFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInitialContextSetupFailureIEValueCaptureS1APERABIEContainerList(v *s26.InitialContextSetupFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEContainer(v *s18.ERABDataForwardingItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEContainer(v *s18.ERABDataForwardingItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEContainer(v *s18.ERABFailedToResumeItemResumeReqIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEContainer(v *s18.ERABFailedToResumeItemResumeReqIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEContainer(v *s18.ERABFailedToResumeItemResumeResIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEContainer(v *s18.ERABFailedToResumeItemResumeResIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEContainer(v *s18.ERABFailedtoSetupItemHOReqAckIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEContainer(v *s18.ERABFailedtoSetupItemHOReqAckIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABItemIEValueCaptureS1APProtocolIEContainer(v *s19.ERABItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABItemIEValueCompareS1APProtocolIEContainer(v *s19.ERABItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEContainer(v *s19.ERABModifyItemBearerModConfIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEContainer(v *s19.ERABModifyItemBearerModConfIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEContainer(v *s19.ERABModifyItemBearerModResIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEContainer(v *s19.ERABModifyItemBearerModResIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainer(v *s19.ERABNotToBeModifiedItemBearerModIndIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainer(v *s19.ERABNotToBeModifiedItemBearerModIndIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEContainer(v *s19.ERABReleaseItemBearerRelCompIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEContainer(v *s19.ERABReleaseItemBearerRelCompIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEContainer(v *s19.ERABSetupItemBearerSUResIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEContainer(v *s19.ERABSetupItemBearerSUResIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainer(v *s19.ERABSetupItemCtxtSUResIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainer(v *s19.ERABSetupItemCtxtSUResIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainer(v *s20.ERABToBeModifiedItemBearerModIndIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainer(v *s20.ERABToBeModifiedItemBearerModIndIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEContainer(v *s20.ERABToBeSwitchedULItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEContainer(v *s20.ERABToBeSwitchedULItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEContainer(v *s20.ERABUsageReportItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemIEValueCompareS1APProtocolIEContainer(v *s20.ERABUsageReportItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolErrorIEContainerList(v *s18.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolErrorIEContainerList(v *s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolErrorIEContainerList(v *s18.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolErrorIEContainerList(v *s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolErrorIEContainerList(v *s18.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolErrorIEContainerList(v *s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolErrorIEContainerList(v *s18.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.ERABItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABItemIEValueCompareS1APProtocolErrorIEContainerList(v *s19.ERABItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolErrorIEContainerList(v *s19.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolErrorIEContainerList(v *s19.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolErrorIEContainerList(v *s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolErrorIEContainerList(v *s19.ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolErrorIEContainerList(v *s19.ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolErrorIEContainerList(v *s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolErrorIEContainerList(v *s19.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolErrorIEContainerList(v *s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolErrorIEContainerList(v *s20.ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolErrorIEContainerList(v *s20.ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s20.ERABUsageReportItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemIEValueCompareS1APProtocolErrorIEContainerList(v *s20.ERABUsageReportItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *s26.HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelIEValueCaptureS1APProtocolErrorIEContainerList(v *s21.HandoverCancelIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelIEValueCompareS1APProtocolErrorIEContainerList(v *s21.HandoverCancelIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s26.HandoverFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s26.HandoverFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s26.HandoverPreparationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEContainerList(v *s18.ERABDataForwardingItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEContainerList(v *s18.ERABDataForwardingItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEContainerList(v *s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEContainerList(v *s18.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEContainerList(v *s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEContainerList(v *s18.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEContainerList(v *s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEContainerList(v *s19.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABItemIEValueCaptureS1APProtocolIEContainerList(v *s19.ERABItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABItemIEValueCompareS1APProtocolIEContainerList(v *s19.ERABItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEContainerList(v *s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEContainerList(v *s19.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEContainerList(v *s19.ERABModifyItemBearerModResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEContainerList(v *s19.ERABModifyItemBearerModResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(v *s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(v *s19.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseItemBearerRelCompIEValueCaptureS1APProtocolIEContainerList(v *s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABReleaseItemBearerRelCompIEValueCompareS1APProtocolIEContainerList(v *s19.ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResIEValueCaptureS1APProtocolIEContainerList(v *s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResIEValueCompareS1APProtocolIEContainerList(v *s19.ERABSetupItemBearerSUResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainerList(v *s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainerList(v *s19.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(v *s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(v *s20.ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemIEValueCaptureS1APProtocolIEContainerList(v *s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemIEValueCompareS1APProtocolIEContainerList(v *s20.ERABToBeSwitchedULItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemIEValueCaptureS1APProtocolIEContainerList(v *s20.ERABUsageReportItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemIEValueCompareS1APProtocolIEContainerList(v *s20.ERABUsageReportItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *s26.HandoverCancelAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelIEValueCaptureS1APProtocolIEContainerList(v *s21.HandoverCancelIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelIEValueCompareS1APProtocolIEContainerList(v *s21.HandoverCancelIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverFailureIEValueCaptureS1APProtocolIEContainerList(v *s26.HandoverFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverFailureIEValueCompareS1APProtocolIEContainerList(v *s26.HandoverFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEContainerList(v *s26.HandoverPreparationFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEContainerList(v *s26.HandoverPreparationFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainerList(v *s26.InitialContextSetupFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *s26.HandoverCancelAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *s26.HandoverCancelAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCancelIEValueCaptureS1APProtocolIESingleContainer(v *s21.HandoverCancelIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverCancelIEValueCompareS1APProtocolIESingleContainer(v *s21.HandoverCancelIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCancelIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverFailureIEValueCaptureS1APProtocolIESingleContainer(v *s26.HandoverFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverFailureIEValueCompareS1APProtocolIESingleContainer(v *s26.HandoverFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIESingleContainer(v *s26.HandoverPreparationFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverPreparationFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIESingleContainer(v *s26.HandoverPreparationFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverPreparationFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIESingleContainer(v *s26.InitialContextSetupFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
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
func BridgeCaptureS1APERABFailedToResumeListResumeReq(v *s18.ERABFailedToResumeListResumeReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABFailedToResumeListResumeReq(v *s18.ERABFailedToResumeListResumeReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABFailedToResumeListResumeRes(v *s18.ERABFailedToResumeListResumeRes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABFailedToResumeListResumeRes(v *s18.ERABFailedToResumeListResumeRes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABFailedtoSetupListHOReqAck(v *s19.ERABFailedtoSetupListHOReqAck, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABFailedtoSetupListHOReqAck(v *s19.ERABFailedtoSetupListHOReqAck, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABList(v *s19.ERABList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABList(v *s19.ERABList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABModifyListBearerModConf(v *s19.ERABModifyListBearerModConf, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABModifyListBearerModConf(v *s19.ERABModifyListBearerModConf, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABModifyListBearerModRes(v *s19.ERABModifyListBearerModRes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABModifyListBearerModRes(v *s19.ERABModifyListBearerModRes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABNotToBeModifiedListBearerModInd(v *s19.ERABNotToBeModifiedListBearerModInd, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABNotToBeModifiedListBearerModInd(v *s19.ERABNotToBeModifiedListBearerModInd, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABReleaseListBearerRelComp(v *s19.ERABReleaseListBearerRelComp, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABReleaseListBearerRelComp(v *s19.ERABReleaseListBearerRelComp, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABSetupListBearerSURes(v *s20.ERABSetupListBearerSURes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABSetupListBearerSURes(v *s20.ERABSetupListBearerSURes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABSetupListCtxtSURes(v *s20.ERABSetupListCtxtSURes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABSetupListCtxtSURes(v *s20.ERABSetupListCtxtSURes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABSubjecttoDataForwardingList(v *s20.ERABSubjecttoDataForwardingList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABSubjecttoDataForwardingList(v *s20.ERABSubjecttoDataForwardingList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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
	s21.BridgeCaptureS1APERABLevelQoSParameters(&v.ERABLevelQoSParameters, s)
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
	s21.BridgeCompareS1APERABLevelQoSParameters(&v.ERABLevelQoSParameters, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
func BridgeCaptureS1APERABToBeModifiedListBearerModInd(v *s20.ERABToBeModifiedListBearerModInd, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABToBeModifiedListBearerModInd(v *s20.ERABToBeModifiedListBearerModInd, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABToBeSwitchedULList(v *s20.ERABToBeSwitchedULList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABToBeSwitchedULList(v *s20.ERABToBeSwitchedULList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABUsageReportList(v *s20.ERABUsageReportList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABUsageReportList(v *s20.ERABUsageReportList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APPrivateMessageIEsValue(v *PrivateMessageIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s23.BridgeCaptureS1APPrivateIEID(&v.id, s)
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
	s23.BridgeCompareS1APPrivateIEID(&v.id, s)
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

// HandoverPreparationFailure represents the ASN.1 type HandoverPreparationFailure (SEQUENCE).
type HandoverPreparationFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s26.HandoverPreparationFailureIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s26.HandoverFailureIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s21.HandoverCancelIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s26.HandoverCancelAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
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
	ERABLevelQoSParameters s21.ERABLevelQoSParameters                           `asn1:"tag:1,context,implicit"`
	NASPDU                 s00.NASPDU                                           `asn1:"tag:2,context,implicit"`
	IEExtensions           s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                                 `asn1:"-" json:"-"`
	extCount               int64                                                `asn1:"-" json:"-"`
	extPresent             []bool                                               `asn1:"-" json:"-"`
	extData                [][]byte                                             `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                                    `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                               `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
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
			if err := s26.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverPreparationFailure from APER format.
func (v *HandoverPreparationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *HandoverPreparationFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverPreparationFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s26.HandoverPreparationFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s26.HandoverPreparationFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s26.BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s26.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverFailure from APER format.
func (v *HandoverFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *HandoverFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s26.HandoverFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s26.HandoverFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s26.BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s21.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverCancel from APER format.
func (v *HandoverCancel) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *HandoverCancel) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverCancel{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s21.HandoverCancelIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s21.HandoverCancelIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s21.BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverCancelAcknowledge from APER format.
func (v *HandoverCancelAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *HandoverCancelAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverCancelAcknowledge{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s26.HandoverCancelAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s26.HandoverCancelAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERERABToBeModifiedListBearerModReqListValue struct {
	Value ERABToBeModifiedListBearerModReq
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := s21.BridgeERABLevelQoSParametersMethodMarshalAPERTo(&v.ERABLevelQoSParameters, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeModifiedItemBearerModReq from APER format.
func (v *ERABToBeModifiedItemBearerModReq) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ERABToBeModifiedItemBearerModReq) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifiedItemBearerModReq{}
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
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	toleranceMark_erablevelqosparameters := bb.EnterComponent("ERABLevelQoSParameters")
	if err := s21.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&v.ERABLevelQoSParameters, bb); err != nil {
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
		tmp_ieextensions := make(s24.ERABToBeModifyItemBearerModReqExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s24.ERABToBeModifyItemBearerModReqExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s24.BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ERABToBeModifiedItemBearerModReq) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeModifiedItemBearerModReq", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverCancel", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverCancelAcknowledge", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverFailure", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverPreparationFailure", v.receivedLocation, v.perPadding)
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
func BridgeEqualPrivateID(a, b s23.PrivateIEID, budget *aper.DecodeBudget) bool {
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
	id     s23.PrivateIEID
	opaque aper.OpaqueOpenType
	valid  bool
}

// TS 36.413 V19.2.0 §9.3.7: compare the semantic private ID without replay padding.
func (v PrivateMessageIEsValue) matchesID(id s23.PrivateIEID, budgets ...*aper.DecodeBudget) bool {
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
func (PrivateMessageIEsValue) decode(id s23.PrivateIEID, raw aper.OpaqueOpenType) (PrivateMessageIEsValue, error) {
	if err := raw.Observe(aper.UnknownIE); err != nil {
		return PrivateMessageIEsValue{}, err
	}
	owned, err := s25.BridgeClonePrivateID(id, raw.BudgetBuffer().Budget())
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
func (PrivateMessageIETable) NewOpaque(id s23.PrivateIEID, criticality s00.Criticality, data []byte) (PrivateMessageIEsValuePrivateIEField, error) {
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	if criticality < 0 || criticality > 2 {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(fmt.Errorf("invalid private IE criticality %d", criticality), "Opaque")
	}
	if _, err := s23.BridgePrivateIEIDMethodMarshalAPERBudget(&id, budget, true); err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	owned, err := s25.BridgeClonePrivateID(id, budget)
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
func BridgeERABToBeModifiedItemBearerModReqIEFieldMethodMarshalAPERTo(v *ERABToBeModifiedItemBearerModReqIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeModifiedItemBearerModReqIEFieldMethodUnmarshalAPERFrom(v *ERABToBeModifiedItemBearerModReqIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeERABToBeModifiedItemBearerModReqIEValueFieldRowERABToBeModifiedItemBearerModReq(v *ERABToBeModifiedItemBearerModReqIEValue) **ERABToBeModifiedItemBearerModReq {
	return &v.rowERABToBeModifiedItemBearerModReq
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodMatchesID(v ERABToBeModifiedItemBearerModReqIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeModifiedItemBearerModReqIEValueMethodRule(v ERABToBeModifiedItemBearerModReqIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeHandoverCancelAcknowledgeFieldPerPadding(v *HandoverCancelAcknowledge) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(v *HandoverCancelAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverCancelAcknowledgeMethodUnmarshalAPERFrom(v *HandoverCancelAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeHandoverCancelFieldPerPadding(v *HandoverCancel) *aper.FinalPadding { return &v.perPadding }
func BridgeHandoverCancelFieldReceived(v *HandoverCancel) *bool                { return &v.received }
func BridgeHandoverCancelFieldReceivedAbsolute(v *HandoverCancel) *bool        { return &v.receivedAbsolute }
func BridgeHandoverCancelFieldReceivedBytes(v *HandoverCancel) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverCancelFieldReceivedLocation(v *HandoverCancel) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverCancelMethodMarshalAPERBudget(v *HandoverCancel, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverCancelMethodUnmarshalAPERFrom(v *HandoverCancel, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeHandoverFailureFieldPerPadding(v *HandoverFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverFailureFieldReceived(v *HandoverFailure) *bool         { return &v.received }
func BridgeHandoverFailureFieldReceivedAbsolute(v *HandoverFailure) *bool { return &v.receivedAbsolute }
func BridgeHandoverFailureFieldReceivedBytes(v *HandoverFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverFailureFieldReceivedLocation(v *HandoverFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverFailureMethodMarshalAPERBudget(v *HandoverFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverFailureMethodUnmarshalAPERFrom(v *HandoverFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeHandoverPreparationFailureFieldPerPadding(v *HandoverPreparationFailure) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeHandoverPreparationFailureMethodMarshalAPERBudget(v *HandoverPreparationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverPreparationFailureMethodUnmarshalAPERFrom(v *HandoverPreparationFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgePrivateMessageIEsValueMethodMatchesID(v PrivateMessageIEsValue, a0 s23.PrivateIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePrivateMessageIEsValueMethodRule(v PrivateMessageIEsValue) aper.SourceRule {
	return v.rule()
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
func BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v *PrivateMessageIEsValuePrivateIEField) *aper.Snapshot {
	return &v.replay
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
