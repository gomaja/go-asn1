// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s24 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s24

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
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
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// UERadioCapabilityMatchResponseIEContainer is the concrete ProtocolIEContainer[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEContainer []UERadioCapabilityMatchResponseIEField

// UERadioCapabilityMatchResponseIEField is the concrete ProtocolIEField[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UERadioCapabilityMatchResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEField) WithoutReplay() UERadioCapabilityMatchResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UERadioCapabilityMatchResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UERadioCapabilityMatchResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UERadioCapabilityMatchResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityMatchResponseIEField{}
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
	var zero UERadioCapabilityMatchResponseIEValue

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
func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(v *s14.DAPSResponseInfoListIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(v *s14.DAPSResponseInfoListIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *s22.ENBConfigurationUpdateAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(v *s22.ENBConfigurationUpdateAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(v *s22.ENBConfigurationUpdateFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(v *s22.ENBConfigurationUpdateFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainer(v *s21.ENBStatusTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainer(v *s21.ENBStatusTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(v *s15.ERABAdmittedItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(v *s15.ERABAdmittedItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABAdmittedItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIESingleContainer(v *s15.ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIESingleContainer(v *s15.ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIESingleContainer(v *s15.ERABFailedToResumeItemResumeResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIESingleContainer(v *s15.ERABFailedToResumeItemResumeResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIESingleContainer(v *s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIESingleContainer(v *s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABItemIEValueCaptureS1APProtocolIESingleContainer(v *s16.ERABItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABItemIEValueCompareS1APProtocolIESingleContainer(v *s16.ERABItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIESingleContainer(v *s16.ERABModifyItemBearerModConfIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIESingleContainer(v *s16.ERABModifyItemBearerModConfIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIESingleContainer(v *s16.ERABModifyItemBearerModResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIESingleContainer(v *s16.ERABModifyItemBearerModResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIESingleContainer(v *s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIESingleContainer(v *s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
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
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIESingleContainer(v *s16.ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIESingleContainer(v *s16.ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIESingleContainer(v *s15.ERABDataForwardingItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolIESingleContainer(v *s15.ERABDataForwardingItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEField(v, s)
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

// MDTModeExtensionIELoggedMBSFNMDTIEBinding is the concrete IEBinding[LoggedMBSFNMDT, MDTModeExtensionIEIEValue].
type MDTModeExtensionIELoggedMBSFNMDTIEBinding struct {
	info   s00.FieldInfo
	codec  LoggedMBSFNMDTValueCodec
	inject func(LoggedMBSFNMDT,

	) MDTModeExtensionIEIEValue

	get func(*MDTModeExtensionIEIEValue,

	) (*LoggedMBSFNMDT,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MDTModeExtensionIELoggedMBSFNMDTIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MDTModeExtensionIELoggedMBSFNMDTIEBinding) Codec() LoggedMBSFNMDTValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MDTModeExtensionIELoggedMBSFNMDTIEBinding) New(value LoggedMBSFNMDT,

) (MDTModeExtensionIEIEField, error) {
	if b.inject == nil {
		return MDTModeExtensionIEIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MDTModeExtensionIEIEField{}, aper.OperationError(err, "Value.New")
	}
	return MDTModeExtensionIEIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MDTModeExtensionIELoggedMBSFNMDTIEBinding) Get(field *MDTModeExtensionIEIEField) (*LoggedMBSFNMDT,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LoggedMBSFNMDTValueCodec is the concrete ValueCodec[LoggedMBSFNMDT].
type LoggedMBSFNMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LoggedMBSFNMDT,

		error)
	encode func(LoggedMBSFNMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LoggedMBSFNMDT, aper.DecodeState,

	) (LoggedMBSFNMDT, aper.Snapshot,

	)
	compare func(LoggedMBSFNMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggedMBSFNMDTValueCodec) New(value LoggedMBSFNMDT,

) (LoggedMBSFNMDTAPERValue, error) {
	if c.encode == nil {
		return LoggedMBSFNMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMBSFNMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggedMBSFNMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggedMBSFNMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggedMBSFNMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggedMBSFNMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggedMBSFNMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggedMBSFNMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggedMBSFNMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggedMBSFNMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggedMBSFNMDTValueCodec) EncodeAPER(value LoggedMBSFNMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LoggedMBSFNMDTValueCodec) encodeBudgetValue(value LoggedMBSFNMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggedMBSFNMDTValueCodec) encodeChanged(value LoggedMBSFNMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionIEIEField is the concrete ProtocolIEField[MDTModeExtensionIEIEValue].
type MDTModeExtensionIEIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MDTModeExtensionIEIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEField) WithoutReplay() MDTModeExtensionIEIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MDTModeExtensionIEIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MDTModeExtensionIEIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MDTModeExtensionIEIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MDTModeExtensionIEIEField{}
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
	var zero MDTModeExtensionIEIEValue

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

// IntersystemMeasurementConfigurationValueCodec is the concrete ValueCodec[IntersystemMeasurementConfiguration].
type IntersystemMeasurementConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (IntersystemMeasurementConfiguration,

		error)
	encode func(IntersystemMeasurementConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(IntersystemMeasurementConfiguration, aper.DecodeState,

	) (IntersystemMeasurementConfiguration, aper.Snapshot,

	)
	compare func(IntersystemMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntersystemMeasurementConfigurationValueCodec) New(value IntersystemMeasurementConfiguration,

) (IntersystemMeasurementConfigurationAPERValue, error) {
	if c.encode == nil {
		return IntersystemMeasurementConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntersystemMeasurementConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntersystemMeasurementConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntersystemMeasurementConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntersystemMeasurementConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntersystemMeasurementConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntersystemMeasurementConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntersystemMeasurementConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntersystemMeasurementConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntersystemMeasurementConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntersystemMeasurementConfigurationValueCodec) EncodeAPER(value IntersystemMeasurementConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IntersystemMeasurementConfigurationValueCodec) encodeBudgetValue(value IntersystemMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntersystemMeasurementConfigurationValueCodec) encodeChanged(value IntersystemMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5QoSParametersValueCodec is the concrete ValueCodec[PC5QoSParameters].
type PC5QoSParametersValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5QoSParameters,

		error)
	encode func(PC5QoSParameters,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5QoSParameters, aper.DecodeState,

	) (PC5QoSParameters, aper.Snapshot,

	)
	compare func(PC5QoSParameters, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5QoSParametersValueCodec) New(value PC5QoSParameters,

) (PC5QoSParametersAPERValue, error) {
	if c.encode == nil {
		return PC5QoSParametersAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5QoSParametersAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5QoSParametersAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5QoSParametersAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5QoSParametersValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5QoSParametersAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5QoSParametersAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5QoSParametersAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5QoSParametersAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5QoSParametersAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5QoSParametersValueCodec) EncodeAPER(value PC5QoSParametersAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PC5QoSParametersValueCodec) encodeBudgetValue(value PC5QoSParameters,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5QoSParametersValueCodec) encodeChanged(value PC5QoSParameters,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding is the concrete IEBinding[UERadioCapabilityID, UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) s23.UERadioCapabilityIDMappingResponseIEValue

	get func(*s23.UERadioCapabilityIDMappingResponseIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (s23.UERadioCapabilityIDMappingResponseIEField, error) {
	if b.inject == nil {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return s23.UERadioCapabilityIDMappingResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) Get(field *s23.UERadioCapabilityIDMappingResponseIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding is the concrete IEBinding[UERadioCapability, UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityValueCodec
	inject func(s00.UERadioCapability,

	) s23.UERadioCapabilityIDMappingResponseIEValue

	get func(*s23.UERadioCapabilityIDMappingResponseIEValue,

	) (*s00.UERadioCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) Codec() s02.UERadioCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) New(value s00.UERadioCapability,

) (s23.UERadioCapabilityIDMappingResponseIEField, error) {
	if b.inject == nil {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return s23.UERadioCapabilityIDMappingResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) Get(field *s23.UERadioCapabilityIDMappingResponseIEField) (*s00.UERadioCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityMatchResponseMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UERadioCapabilityMatchResponseIEValue

	get func(*UERadioCapabilityMatchResponseIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UERadioCapabilityMatchResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityMatchResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) Get(field *UERadioCapabilityMatchResponseIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityMatchResponseENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UERadioCapabilityMatchResponseIEValue

	get func(*UERadioCapabilityMatchResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityMatchResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UERadioCapabilityMatchResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityMatchResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityMatchResponseENBUES1APIDIEBinding) Get(field *UERadioCapabilityMatchResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding is the concrete IEBinding[VoiceSupportMatchIndicator, UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s02.VoiceSupportMatchIndicatorValueCodec
	inject func(s00.VoiceSupportMatchIndicator,

	) UERadioCapabilityMatchResponseIEValue

	get func(*UERadioCapabilityMatchResponseIEValue,

	) (*s00.VoiceSupportMatchIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) Codec() s02.VoiceSupportMatchIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) New(value s00.VoiceSupportMatchIndicator,

) (UERadioCapabilityMatchResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityMatchResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) Get(field *UERadioCapabilityMatchResponseIEField) (*s00.VoiceSupportMatchIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) UERadioCapabilityMatchResponseIEValue

	get func(*UERadioCapabilityMatchResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (UERadioCapabilityMatchResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityMatchResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) Get(field *UERadioCapabilityMatchResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// CellStateIndicationValueCodec is the concrete ValueCodec[CellStateIndication].
type CellStateIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellStateIndication,

		error)
	encode func(CellStateIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellStateIndication, aper.DecodeState,

	) (CellStateIndication, aper.Snapshot,

	)
	compare func(CellStateIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellStateIndicationValueCodec) New(value CellStateIndication,

) (CellStateIndicationAPERValue, error) {
	if c.encode == nil {
		return CellStateIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellStateIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellStateIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellStateIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellStateIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellStateIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellStateIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellStateIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellStateIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellStateIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellStateIndicationValueCodec) EncodeAPER(value CellStateIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellStateIndicationValueCodec) encodeBudgetValue(value CellStateIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellStateIndicationValueCodec) encodeChanged(value CellStateIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeValueCodec is the concrete ValueCodec[ENBConfigurationUpdateAcknowledge].
type ENBConfigurationUpdateAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledge,

		error)
	encode func(ENBConfigurationUpdateAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateAcknowledge, aper.DecodeState,

	) (ENBConfigurationUpdateAcknowledge, aper.Snapshot,

	)
	compare func(ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) New(value ENBConfigurationUpdateAcknowledge,

) (ENBConfigurationUpdateAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) EncodeAPER(value ENBConfigurationUpdateAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationUpdateAcknowledgeValueCodec) encodeBudgetValue(value ENBConfigurationUpdateAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateAcknowledgeValueCodec) encodeChanged(value ENBConfigurationUpdateAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateFailureValueCodec is the concrete ValueCodec[ENBConfigurationUpdateFailure].
type ENBConfigurationUpdateFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailure,

		error)
	encode func(ENBConfigurationUpdateFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateFailure, aper.DecodeState,

	) (ENBConfigurationUpdateFailure, aper.Snapshot,

	)
	compare func(ENBConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateFailureValueCodec) New(value ENBConfigurationUpdateFailure,

) (ENBConfigurationUpdateFailureAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateFailureValueCodec) EncodeAPER(value ENBConfigurationUpdateFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationUpdateFailureValueCodec) encodeBudgetValue(value ENBConfigurationUpdateFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateFailureValueCodec) encodeChanged(value ENBConfigurationUpdateFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferValueCodec is the concrete ValueCodec[ENBStatusTransfer].
type ENBStatusTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransfer,

		error)
	encode func(ENBStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransfer, aper.DecodeState,

	) (ENBStatusTransfer, aper.Snapshot,

	)
	compare func(ENBStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferValueCodec) New(value ENBStatusTransfer,

) (ENBStatusTransferAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferValueCodec) EncodeAPER(value ENBStatusTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBStatusTransferValueCodec) encodeBudgetValue(value ENBStatusTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferValueCodec) encodeChanged(value ENBStatusTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterSystemMeasurementParametersValueCodec is the concrete ValueCodec[InterSystemMeasurementParameters].
type InterSystemMeasurementParametersValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemMeasurementParameters,

		error)
	encode func(InterSystemMeasurementParameters,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemMeasurementParameters, aper.DecodeState,

	) (InterSystemMeasurementParameters, aper.Snapshot,

	)
	compare func(InterSystemMeasurementParameters, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemMeasurementParametersValueCodec) New(value InterSystemMeasurementParameters,

) (InterSystemMeasurementParametersAPERValue, error) {
	if c.encode == nil {
		return InterSystemMeasurementParametersAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemMeasurementParametersAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemMeasurementParametersAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemMeasurementParametersAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemMeasurementParametersValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementParametersAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemMeasurementParametersAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemMeasurementParametersAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemMeasurementParametersAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemMeasurementParametersAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemMeasurementParametersValueCodec) EncodeAPER(value InterSystemMeasurementParametersAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterSystemMeasurementParametersValueCodec) encodeBudgetValue(value InterSystemMeasurementParameters,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemMeasurementParametersValueCodec) encodeChanged(value InterSystemMeasurementParameters,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MultiCellLoadReportingRequestValueCodec is the concrete ValueCodec[MultiCellLoadReportingRequest].
type MultiCellLoadReportingRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MultiCellLoadReportingRequest,

		error)
	encode func(MultiCellLoadReportingRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MultiCellLoadReportingRequest, aper.DecodeState,

	) (MultiCellLoadReportingRequest, aper.Snapshot,

	)
	compare func(MultiCellLoadReportingRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MultiCellLoadReportingRequestValueCodec) New(value MultiCellLoadReportingRequest,

) (MultiCellLoadReportingRequestAPERValue, error) {
	if c.encode == nil {
		return MultiCellLoadReportingRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MultiCellLoadReportingRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MultiCellLoadReportingRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MultiCellLoadReportingRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MultiCellLoadReportingRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MultiCellLoadReportingRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MultiCellLoadReportingRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MultiCellLoadReportingRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MultiCellLoadReportingRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MultiCellLoadReportingRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MultiCellLoadReportingRequestValueCodec) EncodeAPER(value MultiCellLoadReportingRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MultiCellLoadReportingRequestValueCodec) encodeBudgetValue(value MultiCellLoadReportingRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MultiCellLoadReportingRequestValueCodec) encodeChanged(value MultiCellLoadReportingRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONtransferRequestContainerValueCodec is the concrete ValueCodec[SONtransferRequestContainer].
type SONtransferRequestContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONtransferRequestContainer,

		error)
	encode func(SONtransferRequestContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONtransferRequestContainer, aper.DecodeState,

	) (SONtransferRequestContainer, aper.Snapshot,

	)
	compare func(SONtransferRequestContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONtransferRequestContainerValueCodec) New(value SONtransferRequestContainer,

) (SONtransferRequestContainerAPERValue, error) {
	if c.encode == nil {
		return SONtransferRequestContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONtransferRequestContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONtransferRequestContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONtransferRequestContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONtransferRequestContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONtransferRequestContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONtransferRequestContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONtransferRequestContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONtransferRequestContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONtransferRequestContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONtransferRequestContainerValueCodec) EncodeAPER(value SONtransferRequestContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONtransferRequestContainerValueCodec) encodeBudgetValue(value SONtransferRequestContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONtransferRequestContainerValueCodec) encodeChanged(value SONtransferRequestContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONtransferResponseContainerValueCodec is the concrete ValueCodec[SONtransferResponseContainer].
type SONtransferResponseContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONtransferResponseContainer,

		error)
	encode func(SONtransferResponseContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONtransferResponseContainer, aper.DecodeState,

	) (SONtransferResponseContainer, aper.Snapshot,

	)
	compare func(SONtransferResponseContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONtransferResponseContainerValueCodec) New(value SONtransferResponseContainer,

) (SONtransferResponseContainerAPERValue, error) {
	if c.encode == nil {
		return SONtransferResponseContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONtransferResponseContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONtransferResponseContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONtransferResponseContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONtransferResponseContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONtransferResponseContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONtransferResponseContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONtransferResponseContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONtransferResponseContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONtransferResponseContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONtransferResponseContainerValueCodec) EncodeAPER(value SONtransferResponseContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONtransferResponseContainerValueCodec) encodeBudgetValue(value SONtransferResponseContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONtransferResponseContainerValueCodec) encodeChanged(value SONtransferResponseContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func DAPSResponseInfoListIEValueERABIEContainerListCodec(table s00.DAPSResponseInfoListIEValueIETable) s14.DAPSResponseInfoListIEValueERABIEContainerListValueCodec {
	codec := DAPSResponseInfoListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.DAPSResponseInfoListIEValueERABIEContainerListValueCodec{}
	}
	return func() s14.DAPSResponseInfoListIEValueERABIEContainerListValueCodec {
		sealed := s14.DAPSResponseInfoListIEValueERABIEContainerListValueCodec{}
		*s14.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.DAPSResponseInfoListIEValueERABIEContainerList, error) {
			value, err := (*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s14.DAPSResponseInfoListIEValueERABIEContainerList(value), err
		}
		*s14.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.DAPSResponseInfoListIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(&codec))(s14.DAPSResponseInfoListIEContainer(value), fresh, budget)
		}
		*s14.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.DAPSResponseInfoListIEValueERABIEContainerList, options aper.DecodeState) (s14.DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.DAPSResponseInfoListIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable) s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := ENBConfigurationUpdateAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	return func() s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec {
		sealed := s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec{}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, error) {
			value, err := (*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList(value), err
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.ENBConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateFailureIEValueERABIEContainerListCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable) s22.ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
	codec := ENBConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
	}
	return func() s22.ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
		sealed := s22.ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
		*s22.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEValueERABIEContainerList, error) {
			value, err := (*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.ENBConfigurationUpdateFailureIEValueERABIEContainerList(value), err
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.ENBConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s22.ENBConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEValueERABIEContainerList, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBStatusTransferIEValueERABIEContainerListCodec(table s00.ENBStatusTransferIEValueIETable) s21.ENBStatusTransferIEValueERABIEContainerListValueCodec {
	codec := ENBStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.ENBStatusTransferIEValueERABIEContainerListValueCodec{}
	}
	return func() s21.ENBStatusTransferIEValueERABIEContainerListValueCodec {
		sealed := s21.ENBStatusTransferIEValueERABIEContainerListValueCodec{}
		*s21.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ENBStatusTransferIEValueERABIEContainerList, error) {
			value, err := (*s21.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.ENBStatusTransferIEValueERABIEContainerList(value), err
		}
		*s21.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.ENBStatusTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeENBStatusTransferIEContainerValueCodecFieldEncode(&codec))(s21.ENBStatusTransferIEContainer(value), fresh, budget)
		}
		*s21.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.ENBStatusTransferIEValueERABIEContainerList, options aper.DecodeState) (s21.ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.ENBStatusTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABAdmittedItemIEValueERABIEContainerListCodec(table s00.ERABAdmittedItemIEValueIETable) s15.ERABAdmittedItemIEValueERABIEContainerListValueCodec {
	codec := ERABAdmittedItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABAdmittedItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s15.ERABAdmittedItemIEValueERABIEContainerListValueCodec {
		sealed := s15.ERABAdmittedItemIEValueERABIEContainerListValueCodec{}
		*s15.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABAdmittedItemIEValueERABIEContainerList, error) {
			value, err := (*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABAdmittedItemIEValueERABIEContainerList(value), err
		}
		*s15.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABAdmittedItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(&codec))(s15.ERABAdmittedItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABAdmittedItemIEValueERABIEContainerList, options aper.DecodeState) (s15.ERABAdmittedItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABAdmittedItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABDataForwardingItemIEValueERABIEContainerListCodec(table s00.ERABDataForwardingItemIEValueIETable) s15.ERABDataForwardingItemIEValueERABIEContainerListValueCodec {
	codec := ERABDataForwardingItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABDataForwardingItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s15.ERABDataForwardingItemIEValueERABIEContainerListValueCodec {
		sealed := s15.ERABDataForwardingItemIEValueERABIEContainerListValueCodec{}
		*s15.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABDataForwardingItemIEValueERABIEContainerList, error) {
			value, err := (*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABDataForwardingItemIEValueERABIEContainerList(value), err
		}
		*s15.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABDataForwardingItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(&codec))(s15.ERABDataForwardingItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABDataForwardingItemIEValueERABIEContainerList, options aper.DecodeState) (s15.ERABDataForwardingItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABDataForwardingItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeReqIEValueERABIEContainerListCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable) s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec{}
	}
	return func() s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, error) {
			value, err := (*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList(value), err
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(&codec))(s15.ERABFailedToResumeItemResumeReqIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeResIEValueERABIEContainerListCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable) s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodec{}
	}
	return func() s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, error) {
			value, err := (*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerList(value), err
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldEncode(&codec))(s15.ERABFailedToResumeItemResumeResIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable) s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec {
	codec := ERABFailedtoSetupItemHOReqAckIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec{}
	}
	return func() s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec {
		sealed := s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec{}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList(value), err
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(&codec))(s16.ERABFailedtoSetupItemHOReqAckIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABItemIEValueERABIEContainerListCodec(table s00.ERABItemIEValueIETable) s16.ERABItemIEValueERABIEContainerListValueCodec {
	codec := ERABItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s16.ERABItemIEValueERABIEContainerListValueCodec {
		sealed := s16.ERABItemIEValueERABIEContainerListValueCodec{}
		*s16.BridgeERABItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABItemIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABItemIEValueERABIEContainerList(value), err
		}
		*s16.BridgeERABItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABItemIEContainerValueCodecFieldEncode(&codec))(s16.ERABItemIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABItemIEValueERABIEContainerList, options aper.DecodeState) (s16.ERABItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModConfIEValueERABIEContainerListCodec(table s00.ERABModifyItemBearerModConfIEValueIETable) s16.ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec {
	codec := ERABModifyItemBearerModConfIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec{}
	}
	return func() s16.ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec {
		sealed := s16.ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec{}
		*s16.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABModifyItemBearerModConfIEValueERABIEContainerList(value), err
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABModifyItemBearerModConfIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(&codec))(s16.ERABModifyItemBearerModConfIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModConfIEValueERABIEContainerList, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModConfIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModResIEValueERABIEContainerListCodec(table s00.ERABModifyItemBearerModResIEValueIETable) s16.ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec {
	codec := ERABModifyItemBearerModResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec{}
	}
	return func() s16.ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec {
		sealed := s16.ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec{}
		*s16.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABModifyItemBearerModResIEValueERABIEContainerList(value), err
		}
		*s16.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABModifyItemBearerModResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(&codec))(s16.ERABModifyItemBearerModResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModResIEValueERABIEContainerList, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable) s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec {
	codec := ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec{}
	}
	return func() s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec {
		sealed := s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec{}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList(value), err
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s16.ERABNotToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
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
func ERABSetupItemCtxtSUResIEValueERABIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s16.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec{}
	}
	return func() s16.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec {
		sealed := s16.ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec{}
		*s16.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEValueERABIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABSetupItemCtxtSUResIEValueERABIEContainerList(value), err
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABSetupItemCtxtSUResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEValueERABIEContainerList, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DAPSResponseInfoListIEValueIEFieldTableCodec(table s00.DAPSResponseInfoListIEValueIETable) s14.DAPSResponseInfoListIEFieldValueCodec {
	if !*s00.BridgeDAPSResponseInfoListIEValueIETableFieldBound(&table) {
		return s14.DAPSResponseInfoListIEFieldValueCodec{}
	}
	return func() s14.DAPSResponseInfoListIEFieldValueCodec {
		sealed := s14.DAPSResponseInfoListIEFieldValueCodec{}
		*s14.BridgeDAPSResponseInfoListIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.DAPSResponseInfoListIEField, error) {
			var field s14.DAPSResponseInfoListIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s14.BridgeDAPSResponseInfoListIEFieldValueCodecFieldEncode(&sealed) = func(field s14.DAPSResponseInfoListIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeDAPSResponseInfoListIEFieldValueCodecFieldCapture(&sealed) = func(v s14.DAPSResponseInfoListIEField, options aper.DecodeState) (s14.DAPSResponseInfoListIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s14.BridgeDAPSResponseInfoListIEFieldValueCodecFieldCompare(&sealed) = func(v s14.DAPSResponseInfoListIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeDAPSResponseInfoListIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable) s22.ENBConfigurationUpdateAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeENBConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&table) {
		return s22.ENBConfigurationUpdateAcknowledgeIEFieldValueCodec{}
	}
	return func() s22.ENBConfigurationUpdateAcknowledgeIEFieldValueCodec {
		sealed := s22.ENBConfigurationUpdateAcknowledgeIEFieldValueCodec{}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEField, error) {
			var field s22.ENBConfigurationUpdateAcknowledgeIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldEncode(&sealed) = func(field s22.ENBConfigurationUpdateAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEField, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateFailureIEValueIEFieldTableCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable) s22.ENBConfigurationUpdateFailureIEFieldValueCodec {
	if !*s00.BridgeENBConfigurationUpdateFailureIEValueIETableFieldBound(&table) {
		return s22.ENBConfigurationUpdateFailureIEFieldValueCodec{}
	}
	return func() s22.ENBConfigurationUpdateFailureIEFieldValueCodec {
		sealed := s22.ENBConfigurationUpdateFailureIEFieldValueCodec{}
		*s22.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEField, error) {
			var field s22.ENBConfigurationUpdateFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s22.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s22.ENBConfigurationUpdateFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeENBConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s22.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEField, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s22.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBStatusTransferIEValueIEFieldTableCodec(table s00.ENBStatusTransferIEValueIETable) s21.ENBStatusTransferIEFieldValueCodec {
	if !*s00.BridgeENBStatusTransferIEValueIETableFieldBound(&table) {
		return s21.ENBStatusTransferIEFieldValueCodec{}
	}
	return func() s21.ENBStatusTransferIEFieldValueCodec {
		sealed := s21.ENBStatusTransferIEFieldValueCodec{}
		*s21.BridgeENBStatusTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ENBStatusTransferIEField, error) {
			var field s21.ENBStatusTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s21.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s21.BridgeENBStatusTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s21.ENBStatusTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s21.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s21.BridgeENBStatusTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s21.ENBStatusTransferIEField, options aper.DecodeState) (s21.ENBStatusTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s21.BridgeENBStatusTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s21.ENBStatusTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeENBStatusTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABAdmittedItemIEValueIEFieldTableCodec(table s00.ERABAdmittedItemIEValueIETable) s15.ERABAdmittedItemIEFieldValueCodec {
	if !*s00.BridgeERABAdmittedItemIEValueIETableFieldBound(&table) {
		return s15.ERABAdmittedItemIEFieldValueCodec{}
	}
	return func() s15.ERABAdmittedItemIEFieldValueCodec {
		sealed := s15.ERABAdmittedItemIEFieldValueCodec{}
		*s15.BridgeERABAdmittedItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABAdmittedItemIEField, error) {
			var field s15.ERABAdmittedItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s15.BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s15.BridgeERABAdmittedItemIEFieldValueCodecFieldEncode(&sealed) = func(field s15.ERABAdmittedItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s15.BridgeERABAdmittedItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s15.BridgeERABAdmittedItemIEFieldValueCodecFieldCapture(&sealed) = func(v s15.ERABAdmittedItemIEField, options aper.DecodeState) (s15.ERABAdmittedItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s15.BridgeERABAdmittedItemIEFieldValueCodecFieldCompare(&sealed) = func(v s15.ERABAdmittedItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABAdmittedItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABDataForwardingItemIEValueIEFieldTableCodec(table s00.ERABDataForwardingItemIEValueIETable) s15.ERABDataForwardingItemIEFieldValueCodec {
	if !*s00.BridgeERABDataForwardingItemIEValueIETableFieldBound(&table) {
		return s15.ERABDataForwardingItemIEFieldValueCodec{}
	}
	return func() s15.ERABDataForwardingItemIEFieldValueCodec {
		sealed := s15.ERABDataForwardingItemIEFieldValueCodec{}
		*s15.BridgeERABDataForwardingItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABDataForwardingItemIEField, error) {
			var field s15.ERABDataForwardingItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s15.BridgeERABDataForwardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s15.BridgeERABDataForwardingItemIEFieldValueCodecFieldEncode(&sealed) = func(field s15.ERABDataForwardingItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s15.BridgeERABDataForwardingItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s15.BridgeERABDataForwardingItemIEFieldValueCodecFieldCapture(&sealed) = func(v s15.ERABDataForwardingItemIEField, options aper.DecodeState) (s15.ERABDataForwardingItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s15.BridgeERABDataForwardingItemIEFieldValueCodecFieldCompare(&sealed) = func(v s15.ERABDataForwardingItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABDataForwardingItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeReqIEValueIEFieldTableCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable) s15.ERABFailedToResumeItemResumeReqIEFieldValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeReqIEValueIETableFieldBound(&table) {
		return s15.ERABFailedToResumeItemResumeReqIEFieldValueCodec{}
	}
	return func() s15.ERABFailedToResumeItemResumeReqIEFieldValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeReqIEFieldValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEField, error) {
			var field s15.ERABFailedToResumeItemResumeReqIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s15.BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldEncode(&sealed) = func(field s15.ERABFailedToResumeItemResumeReqIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s15.BridgeERABFailedToResumeItemResumeReqIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEField, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeResIEValueIEFieldTableCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable) s15.ERABFailedToResumeItemResumeResIEFieldValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeResIEValueIETableFieldBound(&table) {
		return s15.ERABFailedToResumeItemResumeResIEFieldValueCodec{}
	}
	return func() s15.ERABFailedToResumeItemResumeResIEFieldValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeResIEFieldValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEField, error) {
			var field s15.ERABFailedToResumeItemResumeResIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s15.BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldEncode(&sealed) = func(field s15.ERABFailedToResumeItemResumeResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s15.BridgeERABFailedToResumeItemResumeResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEField, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedtoSetupItemHOReqAckIEValueIEFieldTableCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable) s16.ERABFailedtoSetupItemHOReqAckIEFieldValueCodec {
	if !*s00.BridgeERABFailedtoSetupItemHOReqAckIEValueIETableFieldBound(&table) {
		return s16.ERABFailedtoSetupItemHOReqAckIEFieldValueCodec{}
	}
	return func() s16.ERABFailedtoSetupItemHOReqAckIEFieldValueCodec {
		sealed := s16.ERABFailedtoSetupItemHOReqAckIEFieldValueCodec{}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEField, error) {
			var field s16.ERABFailedtoSetupItemHOReqAckIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABFailedtoSetupItemHOReqAckIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEField, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABItemIEValueIEFieldTableCodec(table s00.ERABItemIEValueIETable) s16.ERABItemIEFieldValueCodec {
	if !*s00.BridgeERABItemIEValueIETableFieldBound(&table) {
		return s16.ERABItemIEFieldValueCodec{}
	}
	return func() s16.ERABItemIEFieldValueCodec {
		sealed := s16.ERABItemIEFieldValueCodec{}
		*s16.BridgeERABItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABItemIEField, error) {
			var field s16.ERABItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeERABItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s16.BridgeERABItemIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeERABItemIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABItemIEField, options aper.DecodeState) (s16.ERABItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s16.BridgeERABItemIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModConfIEValueIEFieldTableCodec(table s00.ERABModifyItemBearerModConfIEValueIETable) s16.ERABModifyItemBearerModConfIEFieldValueCodec {
	if !*s00.BridgeERABModifyItemBearerModConfIEValueIETableFieldBound(&table) {
		return s16.ERABModifyItemBearerModConfIEFieldValueCodec{}
	}
	return func() s16.ERABModifyItemBearerModConfIEFieldValueCodec {
		sealed := s16.ERABModifyItemBearerModConfIEFieldValueCodec{}
		*s16.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEField, error) {
			var field s16.ERABModifyItemBearerModConfIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s16.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABModifyItemBearerModConfIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABModifyItemBearerModConfIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModConfIEField, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s16.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModConfIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModResIEValueIEFieldTableCodec(table s00.ERABModifyItemBearerModResIEValueIETable) s16.ERABModifyItemBearerModResIEFieldValueCodec {
	if !*s00.BridgeERABModifyItemBearerModResIEValueIETableFieldBound(&table) {
		return s16.ERABModifyItemBearerModResIEFieldValueCodec{}
	}
	return func() s16.ERABModifyItemBearerModResIEFieldValueCodec {
		sealed := s16.ERABModifyItemBearerModResIEFieldValueCodec{}
		*s16.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEField, error) {
			var field s16.ERABModifyItemBearerModResIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s16.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABModifyItemBearerModResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABModifyItemBearerModResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModResIEField, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s16.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABNotToBeModifiedItemBearerModIndIEValueIEFieldTableCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable) s16.ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec {
	if !*s00.BridgeERABNotToBeModifiedItemBearerModIndIEValueIETableFieldBound(&table) {
		return s16.ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec{}
	}
	return func() s16.ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec {
		sealed := s16.ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec{}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEField, error) {
			var field s16.ERABNotToBeModifiedItemBearerModIndIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABNotToBeModifiedItemBearerModIndIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEField, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
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
func ERABSetupItemCtxtSUResIEValueIEFieldTableCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s16.ERABSetupItemCtxtSUResIEFieldValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResIEValueIETableFieldBound(&table) {
		return s16.ERABSetupItemCtxtSUResIEFieldValueCodec{}
	}
	return func() s16.ERABSetupItemCtxtSUResIEFieldValueCodec {
		sealed := s16.ERABSetupItemCtxtSUResIEFieldValueCodec{}
		*s16.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEField, error) {
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
		*s16.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldEncode(&sealed) = func(field s16.ERABSetupItemCtxtSUResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEField, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEField, aper.Snapshot,
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
		*s16.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
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
func DAPSResponseInfoListIEValueIETableCodec(table s00.DAPSResponseInfoListIEValueIETable, bounds aper.ListBounds) s14.DAPSResponseInfoListIEContainerValueCodec {
	if !*s00.BridgeDAPSResponseInfoListIEValueIETableFieldBound(&table) {
		return s14.DAPSResponseInfoListIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.DAPSResponseInfoListIEContainerValueCodec {
		sealed := s14.DAPSResponseInfoListIEContainerValueCodec{}
		*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.DAPSResponseInfoListIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.DAPSResponseInfoListIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.DAPSResponseInfoListIEField
					if err := s14.BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(&sealed) = func(fields s14.DAPSResponseInfoListIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldCapture(&sealed) = func(v s14.DAPSResponseInfoListIEContainer, options aper.DecodeState) (s14.DAPSResponseInfoListIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldCompare(&sealed) = func(v s14.DAPSResponseInfoListIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateAcknowledgeIEValueIETableCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable, bounds aper.ListBounds) s22.ENBConfigurationUpdateAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeENBConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&table) {
		return s22.ENBConfigurationUpdateAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.ENBConfigurationUpdateAcknowledgeIEContainerValueCodec {
		sealed := s22.ENBConfigurationUpdateAcknowledgeIEContainerValueCodec{}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.ENBConfigurationUpdateAcknowledgeIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.ENBConfigurationUpdateAcknowledgeIEField
					if err := s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.ENBConfigurationUpdateAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEContainer, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateFailureIEValueIETableCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s22.ENBConfigurationUpdateFailureIEContainerValueCodec {
	if !*s00.BridgeENBConfigurationUpdateFailureIEValueIETableFieldBound(&table) {
		return s22.ENBConfigurationUpdateFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.ENBConfigurationUpdateFailureIEContainerValueCodec {
		sealed := s22.ENBConfigurationUpdateFailureIEContainerValueCodec{}
		*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.ENBConfigurationUpdateFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.ENBConfigurationUpdateFailureIEField
					if err := s22.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.ENBConfigurationUpdateFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeENBConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEContainer, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBStatusTransferIEValueIETableCodec(table s00.ENBStatusTransferIEValueIETable, bounds aper.ListBounds) s21.ENBStatusTransferIEContainerValueCodec {
	if !*s00.BridgeENBStatusTransferIEValueIETableFieldBound(&table) {
		return s21.ENBStatusTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s21.ENBStatusTransferIEContainerValueCodec {
		sealed := s21.ENBStatusTransferIEContainerValueCodec{}
		*s21.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ENBStatusTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.ENBStatusTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.ENBStatusTransferIEField
					if err := s21.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s21.BridgeENBStatusTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s21.ENBStatusTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s21.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s21.BridgeENBStatusTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s21.ENBStatusTransferIEContainer, options aper.DecodeState) (s21.ENBStatusTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeENBStatusTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s21.ENBStatusTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeENBStatusTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABAdmittedItemIEValueIETableCodec(table s00.ERABAdmittedItemIEValueIETable, bounds aper.ListBounds) s15.ERABAdmittedItemIEContainerValueCodec {
	if !*s00.BridgeERABAdmittedItemIEValueIETableFieldBound(&table) {
		return s15.ERABAdmittedItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s15.ERABAdmittedItemIEContainerValueCodec {
		sealed := s15.ERABAdmittedItemIEContainerValueCodec{}
		*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABAdmittedItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s15.ERABAdmittedItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s15.ERABAdmittedItemIEField
					if err := s15.BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s15.ERABAdmittedItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s15.BridgeERABAdmittedItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldCapture(&sealed) = func(v s15.ERABAdmittedItemIEContainer, options aper.DecodeState) (s15.ERABAdmittedItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldCompare(&sealed) = func(v s15.ERABAdmittedItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABDataForwardingItemIEValueIETableCodec(table s00.ERABDataForwardingItemIEValueIETable, bounds aper.ListBounds) s15.ERABDataForwardingItemIEContainerValueCodec {
	if !*s00.BridgeERABDataForwardingItemIEValueIETableFieldBound(&table) {
		return s15.ERABDataForwardingItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s15.ERABDataForwardingItemIEContainerValueCodec {
		sealed := s15.ERABDataForwardingItemIEContainerValueCodec{}
		*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABDataForwardingItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s15.ERABDataForwardingItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s15.ERABDataForwardingItemIEField
					if err := s15.BridgeERABDataForwardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s15.ERABDataForwardingItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s15.BridgeERABDataForwardingItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldCapture(&sealed) = func(v s15.ERABDataForwardingItemIEContainer, options aper.DecodeState) (s15.ERABDataForwardingItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldCompare(&sealed) = func(v s15.ERABDataForwardingItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeReqIEValueIETableCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable, bounds aper.ListBounds) s15.ERABFailedToResumeItemResumeReqIEContainerValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeReqIEValueIETableFieldBound(&table) {
		return s15.ERABFailedToResumeItemResumeReqIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s15.ERABFailedToResumeItemResumeReqIEContainerValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeReqIEContainerValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s15.ERABFailedToResumeItemResumeReqIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s15.ERABFailedToResumeItemResumeReqIEField
					if err := s15.BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(&sealed) = func(fields s15.ERABFailedToResumeItemResumeReqIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s15.BridgeERABFailedToResumeItemResumeReqIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEContainer, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeResIEValueIETableCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable, bounds aper.ListBounds) s15.ERABFailedToResumeItemResumeResIEContainerValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeResIEValueIETableFieldBound(&table) {
		return s15.ERABFailedToResumeItemResumeResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s15.ERABFailedToResumeItemResumeResIEContainerValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeResIEContainerValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s15.ERABFailedToResumeItemResumeResIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s15.ERABFailedToResumeItemResumeResIEField
					if err := s15.BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldEncode(&sealed) = func(fields s15.ERABFailedToResumeItemResumeResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s15.BridgeERABFailedToResumeItemResumeResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEContainer, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedtoSetupItemHOReqAckIEValueIETableCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable, bounds aper.ListBounds) s16.ERABFailedtoSetupItemHOReqAckIEContainerValueCodec {
	if !*s00.BridgeERABFailedtoSetupItemHOReqAckIEValueIETableFieldBound(&table) {
		return s16.ERABFailedtoSetupItemHOReqAckIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.ERABFailedtoSetupItemHOReqAckIEContainerValueCodec {
		sealed := s16.ERABFailedtoSetupItemHOReqAckIEContainerValueCodec{}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.ERABFailedtoSetupItemHOReqAckIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.ERABFailedtoSetupItemHOReqAckIEField
					if err := s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(&sealed) = func(fields s16.ERABFailedtoSetupItemHOReqAckIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldCapture(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEContainer, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldCompare(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABItemIEValueIETableCodec(table s00.ERABItemIEValueIETable, bounds aper.ListBounds) s16.ERABItemIEContainerValueCodec {
	if !*s00.BridgeERABItemIEValueIETableFieldBound(&table) {
		return s16.ERABItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.ERABItemIEContainerValueCodec {
		sealed := s16.ERABItemIEContainerValueCodec{}
		*s16.BridgeERABItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.ERABItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.ERABItemIEField
					if err := s16.BridgeERABItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s16.BridgeERABItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s16.ERABItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeERABItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeERABItemIEContainerValueCodecFieldCapture(&sealed) = func(v s16.ERABItemIEContainer, options aper.DecodeState) (s16.ERABItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABItemIEContainerValueCodecFieldCompare(&sealed) = func(v s16.ERABItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModConfIEValueIETableCodec(table s00.ERABModifyItemBearerModConfIEValueIETable, bounds aper.ListBounds) s16.ERABModifyItemBearerModConfIEContainerValueCodec {
	if !*s00.BridgeERABModifyItemBearerModConfIEValueIETableFieldBound(&table) {
		return s16.ERABModifyItemBearerModConfIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.ERABModifyItemBearerModConfIEContainerValueCodec {
		sealed := s16.ERABModifyItemBearerModConfIEContainerValueCodec{}
		*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.ERABModifyItemBearerModConfIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.ERABModifyItemBearerModConfIEField
					if err := s16.BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(&sealed) = func(fields s16.ERABModifyItemBearerModConfIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeERABModifyItemBearerModConfIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModConfIEContainer, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModConfIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModResIEValueIETableCodec(table s00.ERABModifyItemBearerModResIEValueIETable, bounds aper.ListBounds) s16.ERABModifyItemBearerModResIEContainerValueCodec {
	if !*s00.BridgeERABModifyItemBearerModResIEValueIETableFieldBound(&table) {
		return s16.ERABModifyItemBearerModResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.ERABModifyItemBearerModResIEContainerValueCodec {
		sealed := s16.ERABModifyItemBearerModResIEContainerValueCodec{}
		*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.ERABModifyItemBearerModResIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.ERABModifyItemBearerModResIEField
					if err := s16.BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(&sealed) = func(fields s16.ERABModifyItemBearerModResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeERABModifyItemBearerModResIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModResIEContainer, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s16.ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec {
	if !*s00.BridgeERABNotToBeModifiedItemBearerModIndIEValueIETableFieldBound(&table) {
		return s16.ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec {
		sealed := s16.ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec{}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.ERABNotToBeModifiedItemBearerModIndIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.ERABNotToBeModifiedItemBearerModIndIEField
					if err := s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&sealed) = func(fields s16.ERABNotToBeModifiedItemBearerModIndIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldCapture(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEContainer, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldCompare(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
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
func DAPSResponseInfoListIEValueProtocolErrorIEContainerListCodec(table s00.DAPSResponseInfoListIEValueIETable) s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec {
	codec := DAPSResponseInfoListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec{}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerList(value), err
		}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(&codec))(s14.DAPSResponseInfoListIEContainer(value), fresh, budget)
		}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable) s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBConfigurationUpdateAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList(value), err
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.ENBConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable) s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList(value), err
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s22.ENBConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBStatusTransferIEValueProtocolErrorIEContainerListCodec(table s00.ENBStatusTransferIEValueIETable) s21.ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s21.ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s21.ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s21.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ENBStatusTransferIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s21.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.ENBStatusTransferIEValueProtocolErrorIEContainerList(value), err
		}
		*s21.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.ENBStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeENBStatusTransferIEContainerValueCodecFieldEncode(&codec))(s21.ENBStatusTransferIEContainer(value), fresh, budget)
		}
		*s21.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.ENBStatusTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s21.ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.ENBStatusTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeENBStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABAdmittedItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABAdmittedItemIEValueIETable) s15.ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABAdmittedItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s15.ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s15.ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s15.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABAdmittedItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABAdmittedItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s15.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABAdmittedItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(&codec))(s15.ERABAdmittedItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABAdmittedItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s15.ERABAdmittedItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABAdmittedItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABAdmittedItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABDataForwardingItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABDataForwardingItemIEValueIETable) s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABDataForwardingItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s15.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s15.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(&codec))(s15.ERABDataForwardingItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable) s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList(value), err
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(&codec))(s15.ERABFailedToResumeItemResumeReqIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable) s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList(value), err
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldEncode(&codec))(s15.ERABFailedToResumeItemResumeResIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable) s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABFailedtoSetupItemHOReqAckIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec{}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList(value), err
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(&codec))(s16.ERABFailedtoSetupItemHOReqAckIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABItemIEValueIETable) s16.ERABItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s16.ERABItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s16.ERABItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s16.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s16.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABItemIEContainerValueCodecFieldEncode(&codec))(s16.ERABItemIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s16.ERABItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListCodec(table s00.ERABModifyItemBearerModConfIEValueIETable) s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABModifyItemBearerModConfIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec{}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList(value), err
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(&codec))(s16.ERABModifyItemBearerModConfIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListCodec(table s00.ERABModifyItemBearerModResIEValueIETable) s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABModifyItemBearerModResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec{}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList(value), err
		}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(&codec))(s16.ERABModifyItemBearerModResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable) s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec{}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList(value), err
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(&codec))(s16.ERABNotToBeModifiedItemBearerModIndIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
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
func ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable) s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec{}
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList(value), err
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

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
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DAPSResponseInfoListIEValueProtocolIEContainerListCodec(table s00.DAPSResponseInfoListIEValueIETable, bounds aper.ListBounds) s14.DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec {
	codec := DAPSResponseInfoListIEValueIETableCodec(table, bounds)
	if *s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s14.DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec {
		sealed := s14.DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec{}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.DAPSResponseInfoListIEValueProtocolIEContainerList, error) {
			value, err := (*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s14.DAPSResponseInfoListIEValueProtocolIEContainerList(value), err
		}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.DAPSResponseInfoListIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(&codec))(s14.DAPSResponseInfoListIEContainer(value), fresh, budget)
		}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.DAPSResponseInfoListIEValueProtocolIEContainerList, options aper.DecodeState) (s14.DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.DAPSResponseInfoListIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable, bounds aper.ListBounds) s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := ENBConfigurationUpdateAcknowledgeIEValueIETableCodec(table, bounds)
	if *s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec {
		sealed := s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, error) {
			value, err := (*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList(value), err
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s22.ENBConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBConfigurationUpdateFailureIEValueProtocolIEContainerListCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
	codec := ENBConfigurationUpdateFailureIEValueIETableCodec(table, bounds)
	if *s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, error) {
			value, err := (*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList(value), err
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s22.ENBConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBStatusTransferIEValueProtocolIEContainerListCodec(table s00.ENBStatusTransferIEValueIETable, bounds aper.ListBounds) s21.ENBStatusTransferIEValueProtocolIEContainerListValueCodec {
	codec := ENBStatusTransferIEValueIETableCodec(table, bounds)
	if *s21.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.ENBStatusTransferIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s21.ENBStatusTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s21.ENBStatusTransferIEValueProtocolIEContainerListValueCodec{}
		*s21.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ENBStatusTransferIEValueProtocolIEContainerList, error) {
			value, err := (*s21.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.ENBStatusTransferIEValueProtocolIEContainerList(value), err
		}
		*s21.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.ENBStatusTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeENBStatusTransferIEContainerValueCodecFieldEncode(&codec))(s21.ENBStatusTransferIEContainer(value), fresh, budget)
		}
		*s21.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.ENBStatusTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s21.ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s21.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.ENBStatusTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABAdmittedItemIEValueProtocolIEContainerListCodec(table s00.ERABAdmittedItemIEValueIETable, bounds aper.ListBounds) s15.ERABAdmittedItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABAdmittedItemIEValueIETableCodec(table, bounds)
	if *s15.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABAdmittedItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s15.ERABAdmittedItemIEValueProtocolIEContainerListValueCodec {
		sealed := s15.ERABAdmittedItemIEValueProtocolIEContainerListValueCodec{}
		*s15.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABAdmittedItemIEValueProtocolIEContainerList, error) {
			value, err := (*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABAdmittedItemIEValueProtocolIEContainerList(value), err
		}
		*s15.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABAdmittedItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(&codec))(s15.ERABAdmittedItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABAdmittedItemIEValueProtocolIEContainerList, options aper.DecodeState) (s15.ERABAdmittedItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s15.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABAdmittedItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABDataForwardingItemIEValueProtocolIEContainerListCodec(table s00.ERABDataForwardingItemIEValueIETable, bounds aper.ListBounds) s15.ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABDataForwardingItemIEValueIETableCodec(table, bounds)
	if *s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s15.ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec {
		sealed := s15.ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec{}
		*s15.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABDataForwardingItemIEValueProtocolIEContainerList, error) {
			value, err := (*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABDataForwardingItemIEValueProtocolIEContainerList(value), err
		}
		*s15.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABDataForwardingItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(&codec))(s15.ERABDataForwardingItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABDataForwardingItemIEValueProtocolIEContainerList, options aper.DecodeState) (s15.ERABDataForwardingItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s15.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABDataForwardingItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListCodec(table s00.ERABFailedToResumeItemResumeReqIEValueIETable, bounds aper.ListBounds) s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeReqIEValueIETableCodec(table, bounds)
	if *s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, error) {
			value, err := (*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList(value), err
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(&codec))(s15.ERABFailedToResumeItemResumeReqIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListCodec(table s00.ERABFailedToResumeItemResumeResIEValueIETable, bounds aper.ListBounds) s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodec {
	codec := ERABFailedToResumeItemResumeResIEValueIETableCodec(table, bounds)
	if *s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodec {
		sealed := s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodec{}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, error) {
			value, err := (*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList(value), err
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeERABFailedToResumeItemResumeResIEContainerValueCodecFieldEncode(&codec))(s15.ERABFailedToResumeItemResumeResIEContainer(value), fresh, budget)
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, options aper.DecodeState) (s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeERABFailedToResumeItemResumeResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListCodec(table s00.ERABFailedtoSetupItemHOReqAckIEValueIETable, bounds aper.ListBounds) s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec {
	codec := ERABFailedtoSetupItemHOReqAckIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec {
		sealed := s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec{}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList(value), err
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(&codec))(s16.ERABFailedtoSetupItemHOReqAckIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, options aper.DecodeState) (s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABItemIEValueProtocolIEContainerListCodec(table s00.ERABItemIEValueIETable, bounds aper.ListBounds) s16.ERABItemIEValueProtocolIEContainerListValueCodec {
	codec := ERABItemIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s16.ERABItemIEValueProtocolIEContainerListValueCodec {
		sealed := s16.ERABItemIEValueProtocolIEContainerListValueCodec{}
		*s16.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABItemIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABItemIEValueProtocolIEContainerList(value), err
		}
		*s16.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABItemIEContainerValueCodecFieldEncode(&codec))(s16.ERABItemIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABItemIEValueProtocolIEContainerList, options aper.DecodeState) (s16.ERABItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s16.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModConfIEValueProtocolIEContainerListCodec(table s00.ERABModifyItemBearerModConfIEValueIETable, bounds aper.ListBounds) s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec {
	codec := ERABModifyItemBearerModConfIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec {
		sealed := s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec{}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerList(value), err
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(&codec))(s16.ERABModifyItemBearerModConfIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, options aper.DecodeState) (s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModResIEValueProtocolIEContainerListCodec(table s00.ERABModifyItemBearerModResIEValueIETable, bounds aper.ListBounds) s16.ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec {
	codec := ERABModifyItemBearerModResIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s16.ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec {
		sealed := s16.ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec{}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABModifyItemBearerModResIEValueProtocolIEContainerList(value), err
		}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABModifyItemBearerModResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(&codec))(s16.ERABModifyItemBearerModResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyItemBearerModResIEValueProtocolIEContainerList, options aper.DecodeState) (s16.ERABModifyItemBearerModResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyItemBearerModResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec(table s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable, bounds aper.ListBounds) s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec {
	codec := ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec(table, bounds)
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
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(&v, &s)
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
			BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func ERABSetupItemCtxtSUResIEValueProtocolIEContainerListCodec(table s00.ERABSetupItemCtxtSUResIEValueIETable, bounds aper.ListBounds) s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec {
	codec := ERABSetupItemCtxtSUResIEValueIETableCodec(table, bounds)
	if *s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec {
		sealed := s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec{}
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, error) {
			value, err := (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList(value), err
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s16.BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(&codec))(s16.ERABSetupItemCtxtSUResIEContainer(value), fresh, budget)
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, options aper.DecodeState) (s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.Snapshot,
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
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// dAPSResponseInfoListIEValueProtocolOpenValue is the concrete protocolOpenValue[DAPSResponseInfoListIEValue].
type DAPSResponseInfoListIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s14.DAPSResponseInfoListIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s14.DAPSResponseInfoListIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEField(v *s14.DAPSResponseInfoListIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s14.BridgeDAPSResponseInfoListIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s14.BridgeDAPSResponseInfoListIEFieldFieldReplay(v), *s14.BridgeDAPSResponseInfoListIEFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEField(v *s14.DAPSResponseInfoListIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s14.BridgeDAPSResponseInfoListIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s14.BridgeDAPSResponseInfoListIEFieldFieldReplay(v), *s14.BridgeDAPSResponseInfoListIEFieldFieldWithoutReplay(v))
}

// eNBConfigurationUpdateAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.ENBConfigurationUpdateAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.ENBConfigurationUpdateAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(v *s22.ENBConfigurationUpdateAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeENBConfigurationUpdateAcknowledgeIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldReplay(v), *s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v))
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(v *s22.ENBConfigurationUpdateAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeENBConfigurationUpdateAcknowledgeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldReplay(v), *s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v))
}

// eNBConfigurationUpdateFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.ENBConfigurationUpdateFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.ENBConfigurationUpdateFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(v *s22.ENBConfigurationUpdateFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeENBConfigurationUpdateFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeENBConfigurationUpdateFailureIEFieldFieldReplay(v), *s22.BridgeENBConfigurationUpdateFailureIEFieldFieldWithoutReplay(v))
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v *s22.ENBConfigurationUpdateFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeENBConfigurationUpdateFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeENBConfigurationUpdateFailureIEFieldFieldReplay(v), *s22.BridgeENBConfigurationUpdateFailureIEFieldFieldWithoutReplay(v))
}

// eNBStatusTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBStatusTransferIEValue].
type ENBStatusTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s21.ENBStatusTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s21.ENBStatusTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBStatusTransferIEValueCaptureS1APProtocolIEField(v *s21.ENBStatusTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s21.BridgeENBStatusTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s21.BridgeENBStatusTransferIEFieldFieldReplay(v), *s21.BridgeENBStatusTransferIEFieldFieldWithoutReplay(v))
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolIEField(v *s21.ENBStatusTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s21.BridgeENBStatusTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s21.BridgeENBStatusTransferIEFieldFieldReplay(v), *s21.BridgeENBStatusTransferIEFieldFieldWithoutReplay(v))
}

// eRABAdmittedItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABAdmittedItemIEValue].
type ERABAdmittedItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s15.ERABAdmittedItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s15.ERABAdmittedItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEField(v *s15.ERABAdmittedItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s15.BridgeERABAdmittedItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s15.BridgeERABAdmittedItemIEFieldFieldReplay(v), *s15.BridgeERABAdmittedItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolIEField(v *s15.ERABAdmittedItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s15.BridgeERABAdmittedItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s15.BridgeERABAdmittedItemIEFieldFieldReplay(v), *s15.BridgeERABAdmittedItemIEFieldFieldWithoutReplay(v))
}

// eRABFailedToResumeItemResumeReqIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedToResumeItemResumeReqIEValue].
type ERABFailedToResumeItemResumeReqIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s15.ERABFailedToResumeItemResumeReqIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s15.ERABFailedToResumeItemResumeReqIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEField(v *s15.ERABFailedToResumeItemResumeReqIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s15.BridgeERABFailedToResumeItemResumeReqIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s15.BridgeERABFailedToResumeItemResumeReqIEFieldFieldReplay(v), *s15.BridgeERABFailedToResumeItemResumeReqIEFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEField(v *s15.ERABFailedToResumeItemResumeReqIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s15.BridgeERABFailedToResumeItemResumeReqIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s15.BridgeERABFailedToResumeItemResumeReqIEFieldFieldReplay(v), *s15.BridgeERABFailedToResumeItemResumeReqIEFieldFieldWithoutReplay(v))
}

// eRABFailedToResumeItemResumeResIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedToResumeItemResumeResIEValue].
type ERABFailedToResumeItemResumeResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s15.ERABFailedToResumeItemResumeResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s15.ERABFailedToResumeItemResumeResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEField(v *s15.ERABFailedToResumeItemResumeResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s15.BridgeERABFailedToResumeItemResumeResIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s15.BridgeERABFailedToResumeItemResumeResIEFieldFieldReplay(v), *s15.BridgeERABFailedToResumeItemResumeResIEFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEField(v *s15.ERABFailedToResumeItemResumeResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s15.BridgeERABFailedToResumeItemResumeResIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s15.BridgeERABFailedToResumeItemResumeResIEFieldFieldReplay(v), *s15.BridgeERABFailedToResumeItemResumeResIEFieldFieldWithoutReplay(v))
}

// eRABFailedtoSetupItemHOReqAckIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.ERABFailedtoSetupItemHOReqAckIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.ERABFailedtoSetupItemHOReqAckIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEField(v *s16.ERABFailedtoSetupItemHOReqAckIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s16.BridgeERABFailedtoSetupItemHOReqAckIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldReplay(v), *s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldWithoutReplay(v))
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEField(v *s16.ERABFailedtoSetupItemHOReqAckIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeERABFailedtoSetupItemHOReqAckIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldReplay(v), *s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldWithoutReplay(v))
}

// eRABItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABItemIEValue].
type ERABItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.ERABItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.ERABItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABItemIEValueCaptureS1APProtocolIEField(v *s16.ERABItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s16.BridgeERABItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s16.BridgeERABItemIEFieldFieldReplay(v), *s16.BridgeERABItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABItemIEValueCompareS1APProtocolIEField(v *s16.ERABItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeERABItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s16.BridgeERABItemIEFieldFieldReplay(v), *s16.BridgeERABItemIEFieldFieldWithoutReplay(v))
}

// eRABModifyItemBearerModConfIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.ERABModifyItemBearerModConfIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.ERABModifyItemBearerModConfIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEField(v *s16.ERABModifyItemBearerModConfIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s16.BridgeERABModifyItemBearerModConfIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s16.BridgeERABModifyItemBearerModConfIEFieldFieldReplay(v), *s16.BridgeERABModifyItemBearerModConfIEFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEField(v *s16.ERABModifyItemBearerModConfIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeERABModifyItemBearerModConfIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s16.BridgeERABModifyItemBearerModConfIEFieldFieldReplay(v), *s16.BridgeERABModifyItemBearerModConfIEFieldFieldWithoutReplay(v))
}

// eRABModifyItemBearerModResIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.ERABModifyItemBearerModResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.ERABModifyItemBearerModResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEField(v *s16.ERABModifyItemBearerModResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s16.BridgeERABModifyItemBearerModResIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s16.BridgeERABModifyItemBearerModResIEFieldFieldReplay(v), *s16.BridgeERABModifyItemBearerModResIEFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEField(v *s16.ERABModifyItemBearerModResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeERABModifyItemBearerModResIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s16.BridgeERABModifyItemBearerModResIEFieldFieldReplay(v), *s16.BridgeERABModifyItemBearerModResIEFieldFieldWithoutReplay(v))
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

func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEField(v *s16.ERABNotToBeModifiedItemBearerModIndIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldReplay(v), *s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v))
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEField(v *s16.ERABNotToBeModifiedItemBearerModIndIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldReplay(v), *s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v))
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

// eRABDataForwardingItemIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABDataForwardingItemIEValue].
type ERABDataForwardingItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s15.ERABDataForwardingItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s15.ERABDataForwardingItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEField(v *s15.ERABDataForwardingItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s15.BridgeERABDataForwardingItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s15.BridgeERABDataForwardingItemIEFieldFieldReplay(v), *s15.BridgeERABDataForwardingItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEField(v *s15.ERABDataForwardingItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s15.BridgeERABDataForwardingItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s15.BridgeERABDataForwardingItemIEFieldFieldReplay(v), *s15.BridgeERABDataForwardingItemIEFieldFieldWithoutReplay(v))
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

// LoggedMBSFNMDTAPERValue is the concrete APERValue[LoggedMBSFNMDT].
type LoggedMBSFNMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   LoggedMBSFNMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggedMBSFNMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMBSFNMDTAPERValue) WithoutReplay() LoggedMBSFNMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntersystemMeasurementConfigurationAPERValue is the concrete APERValue[IntersystemMeasurementConfiguration].
type IntersystemMeasurementConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   IntersystemMeasurementConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntersystemMeasurementConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntersystemMeasurementConfigurationAPERValue) WithoutReplay() IntersystemMeasurementConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5QoSParametersAPERValue is the concrete APERValue[PC5QoSParameters].
type PC5QoSParametersAPERValue struct {
	context s00.BridgeCodecContext
	Value   PC5QoSParameters

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5QoSParametersAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSParametersAPERValue) WithoutReplay() PC5QoSParametersAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellStateIndicationAPERValue is the concrete APERValue[CellStateIndication].
type CellStateIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellStateIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellStateIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellStateIndicationAPERValue) WithoutReplay() CellStateIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateAcknowledgeAPERValue is the concrete APERValue[ENBConfigurationUpdateAcknowledge].
type ENBConfigurationUpdateAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBConfigurationUpdateAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAcknowledgeAPERValue) WithoutReplay() ENBConfigurationUpdateAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateFailureAPERValue is the concrete APERValue[ENBConfigurationUpdateFailure].
type ENBConfigurationUpdateFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBConfigurationUpdateFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateFailureAPERValue) WithoutReplay() ENBConfigurationUpdateFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferAPERValue is the concrete APERValue[ENBStatusTransfer].
type ENBStatusTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBStatusTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferAPERValue) WithoutReplay() ENBStatusTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterSystemMeasurementParametersAPERValue is the concrete APERValue[InterSystemMeasurementParameters].
type InterSystemMeasurementParametersAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterSystemMeasurementParameters

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemMeasurementParametersAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementParametersAPERValue) WithoutReplay() InterSystemMeasurementParametersAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MultiCellLoadReportingRequestAPERValue is the concrete APERValue[MultiCellLoadReportingRequest].
type MultiCellLoadReportingRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   MultiCellLoadReportingRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MultiCellLoadReportingRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MultiCellLoadReportingRequestAPERValue) WithoutReplay() MultiCellLoadReportingRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONtransferRequestContainerAPERValue is the concrete APERValue[SONtransferRequestContainer].
type SONtransferRequestContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONtransferRequestContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONtransferRequestContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONtransferRequestContainerAPERValue) WithoutReplay() SONtransferRequestContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONtransferResponseContainerAPERValue is the concrete APERValue[SONtransferResponseContainer].
type SONtransferResponseContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONtransferResponseContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONtransferResponseContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONtransferResponseContainerAPERValue) WithoutReplay() SONtransferResponseContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeDAPSResponseInfoListIEValueCaptureS1APERABIEContainerList(v *s14.DAPSResponseInfoListIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APERABIEContainerList(v *s14.DAPSResponseInfoListIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APERABIEContainerList(v *s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APERABIEContainerList(v *s22.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(v *s22.ENBConfigurationUpdateFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(v *s22.ENBConfigurationUpdateFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APERABIEContainerList(v *s21.ENBStatusTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APERABIEContainerList(v *s21.ENBStatusTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APERABIEContainerList(v *s15.ERABAdmittedItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APERABIEContainerList(v *s15.ERABAdmittedItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABDataForwardingItemIEValueCaptureS1APERABIEContainerList(v *s15.ERABDataForwardingItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemIEValueCompareS1APERABIEContainerList(v *s15.ERABDataForwardingItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APERABIEContainerList(v *s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APERABIEContainerList(v *s15.ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APERABIEContainerList(v *s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APERABIEContainerList(v *s15.ERABFailedToResumeItemResumeResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APERABIEContainerList(v *s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APERABIEContainerList(v *s16.ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemIEValueCaptureS1APERABIEContainerList(v *s16.ERABItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemIEValueCompareS1APERABIEContainerList(v *s16.ERABItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APERABIEContainerList(v *s16.ERABModifyItemBearerModConfIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfIEValueCompareS1APERABIEContainerList(v *s16.ERABModifyItemBearerModConfIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResIEValueCaptureS1APERABIEContainerList(v *s16.ERABModifyItemBearerModResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResIEValueCompareS1APERABIEContainerList(v *s16.ERABModifyItemBearerModResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APERABIEContainerList(v *s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APERABIEContainerList(v *s16.ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APERABIEContainerList(v *s16.ERABSetupItemCtxtSUResIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APERABIEContainerList(v *s16.ERABSetupItemCtxtSUResIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// MDTModeExtensionIEIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueERABIEContainerList, error)
	encode  func(MDTModeExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEValueERABIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot)
	compare func(MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) New(value MDTModeExtensionIEIEValueERABIEContainerList) (MDTModeExtensionIEIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) EncodeAPER(value MDTModeExtensionIEIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) encodeChanged(value MDTModeExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionIEIEValueERABIEContainerList is the concrete ERABIEContainerList[MDTModeExtensionIEIEValue].
type MDTModeExtensionIEIEValueERABIEContainerList []MDTModeExtensionIEIEValueProtocolIESingleContainer

// MDTModeExtensionIEIEContainer is the concrete ProtocolIEContainer[MDTModeExtensionIEIEValue].
type MDTModeExtensionIEIEContainer []MDTModeExtensionIEIEField

// UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueERABIEContainerList, error)
	encode  func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) New(value UERadioCapabilityMatchResponseIEValueERABIEContainerList) (UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEValueERABIEContainerList is the concrete ERABIEContainerList[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEValueERABIEContainerList []UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer

// MDTModeExtensionIEIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEField, error)
	encode  func(MDTModeExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEField, aper.DecodeState) (MDTModeExtensionIEIEField, aper.Snapshot)
	compare func(MDTModeExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEFieldValueCodec) New(value MDTModeExtensionIEIEField) (MDTModeExtensionIEIEFieldAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEFieldValueCodec) EncodeAPER(value MDTModeExtensionIEIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTModeExtensionIEIEFieldValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEFieldValueCodec) encodeChanged(value MDTModeExtensionIEIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEField, error)
	encode  func(UERadioCapabilityMatchResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEField, aper.DecodeState) (UERadioCapabilityMatchResponseIEField, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) New(value UERadioCapabilityMatchResponseIEField) (UERadioCapabilityMatchResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEContainer(v *s14.DAPSResponseInfoListIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEContainer(v *s14.DAPSResponseInfoListIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEContainer(v *s15.ERABAdmittedItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolIEContainer(v *s15.ERABAdmittedItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEContainer(v *s15.ERABDataForwardingItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEContainer(v *s15.ERABDataForwardingItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEContainer(v *s15.ERABFailedToResumeItemResumeReqIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEContainer(v *s15.ERABFailedToResumeItemResumeReqIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEContainer(v *s15.ERABFailedToResumeItemResumeResIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEContainer(v *s15.ERABFailedToResumeItemResumeResIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEContainer(v *s16.ERABFailedtoSetupItemHOReqAckIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEContainer(v *s16.ERABFailedtoSetupItemHOReqAckIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemIEValueCaptureS1APProtocolIEContainer(v *s16.ERABItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemIEValueCompareS1APProtocolIEContainer(v *s16.ERABItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEContainer(v *s16.ERABModifyItemBearerModConfIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEContainer(v *s16.ERABModifyItemBearerModConfIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEContainer(v *s16.ERABModifyItemBearerModResIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEContainer(v *s16.ERABModifyItemBearerModResIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainer(v *s16.ERABNotToBeModifiedItemBearerModIndIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainer(v *s16.ERABNotToBeModifiedItemBearerModIndIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// MDTModeExtensionIEIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEContainer, error)
	encode  func(MDTModeExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEContainer, aper.DecodeState) (MDTModeExtensionIEIEContainer, aper.Snapshot)
	compare func(MDTModeExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEContainerValueCodec) New(value MDTModeExtensionIEIEContainer) (MDTModeExtensionIEIEContainerAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEContainerValueCodec) EncodeAPER(value MDTModeExtensionIEIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTModeExtensionIEIEContainerValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEContainerValueCodec) encodeChanged(value MDTModeExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEContainer, error)
	encode  func(UERadioCapabilityMatchResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEContainer, aper.DecodeState) (UERadioCapabilityMatchResponseIEContainer, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) New(value UERadioCapabilityMatchResponseIEContainer) (UERadioCapabilityMatchResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolErrorIEContainerList(v *s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolErrorIEContainerList(v *s14.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s22.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s21.ENBStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s21.ENBStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s15.ERABAdmittedItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolErrorIEContainerList(v *s15.ERABAdmittedItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolErrorIEContainerList(v *s15.ERABDataForwardingItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolErrorIEContainerList(v *s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolErrorIEContainerList(v *s15.ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolErrorIEContainerList(v *s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolErrorIEContainerList(v *s15.ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolErrorIEContainerList(v *s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolErrorIEContainerList(v *s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s16.ERABItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemIEValueCompareS1APProtocolErrorIEContainerList(v *s16.ERABItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolErrorIEContainerList(v *s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolErrorIEContainerList(v *s16.ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolErrorIEContainerList(v *s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolErrorIEContainerList(v *s16.ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolErrorIEContainerList(v *s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolErrorIEContainerList(v *s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolErrorIEContainerList(v *s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolErrorIEContainerList(v *s16.ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolErrorIEContainerList, error)
	encode  func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) New(value MDTModeExtensionIEIEValueProtocolErrorIEContainerList) (MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MDTModeExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionIEIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[MDTModeExtensionIEIEValue].
type MDTModeExtensionIEIEValueProtocolErrorIEContainerList []MDTModeExtensionIEIEValueProtocolIESingleContainer

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) New(value UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList []UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer

func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEContainerList(v *s14.DAPSResponseInfoListIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEContainerList(v *s14.DAPSResponseInfoListIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(v *s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(v *s22.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainerList(v *s21.ENBStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainerList(v *s21.ENBStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEContainerList(v *s15.ERABAdmittedItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolIEContainerList(v *s15.ERABAdmittedItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABDataForwardingItemIEValueCaptureS1APProtocolIEContainerList(v *s15.ERABDataForwardingItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemIEValueCompareS1APProtocolIEContainerList(v *s15.ERABDataForwardingItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqIEValueCaptureS1APProtocolIEContainerList(v *s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqIEValueCompareS1APProtocolIEContainerList(v *s15.ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResIEValueCaptureS1APProtocolIEContainerList(v *s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResIEValueCompareS1APProtocolIEContainerList(v *s15.ERABFailedToResumeItemResumeResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedtoSetupItemHOReqAckIEValueCaptureS1APProtocolIEContainerList(v *s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedtoSetupItemHOReqAckIEValueCompareS1APProtocolIEContainerList(v *s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemIEValueCaptureS1APProtocolIEContainerList(v *s16.ERABItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemIEValueCompareS1APProtocolIEContainerList(v *s16.ERABItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfIEValueCaptureS1APProtocolIEContainerList(v *s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfIEValueCompareS1APProtocolIEContainerList(v *s16.ERABModifyItemBearerModConfIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResIEValueCaptureS1APProtocolIEContainerList(v *s16.ERABModifyItemBearerModResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResIEValueCompareS1APProtocolIEContainerList(v *s16.ERABModifyItemBearerModResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCaptureS1APProtocolIEContainerList(v *s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndIEValueCompareS1APProtocolIEContainerList(v *s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCaptureS1APProtocolIEContainerList(v *s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResIEValueCompareS1APProtocolIEContainerList(v *s16.ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolIEContainerList, error)
	encode  func(MDTModeExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) New(value MDTModeExtensionIEIEValueProtocolIEContainerList) (MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) encodeChanged(value MDTModeExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionIEIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[MDTModeExtensionIEIEValue].
type MDTModeExtensionIEIEValueProtocolIEContainerList []MDTModeExtensionIEIEValueProtocolIESingleContainer

// UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, error)
	encode  func(s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) New(value s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList) (s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue {
			sealed := s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{Value: value}
			*s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldReplay(&sealed) = replay
			*s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldContext(&value) == c.context && !fresh && (*s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s23.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, error)
	encode  func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) New(value UERadioCapabilityMatchResponseIEValueProtocolIEContainerList) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEValueProtocolIEContainerList []UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer

func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *s22.ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(v *s22.ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(v *s22.ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APProtocolIESingleContainer(v *s21.ENBStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBStatusTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolIESingleContainer(v *s21.ENBStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBStatusTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// MDTModeExtensionIEIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEValueERABIEContainerListAPERValue) WithoutReplay() MDTModeExtensionIEIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionIEIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[MDTModeExtensionIEIEValue].
type MDTModeExtensionIEIEValueProtocolIESingleContainer = MDTModeExtensionIEIEField

// UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer = UERadioCapabilityMatchResponseIEField

// MDTModeExtensionIEIEFieldAPERValue is the concrete APERValue[ProtocolIEField[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEFieldAPERValue) WithoutReplay() MDTModeExtensionIEIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEFieldAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionIEIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEContainerAPERValue) WithoutReplay() MDTModeExtensionIEIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEContainerAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[MDTModeExtensionIEIEValue]].
type MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue) WithoutReplay() MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UERadioCapabilityMatchResponseIEValue]].
type UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APCellStateIndication(v *CellStateIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APNotificationCellList(&v.NotificationCellList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellStateIndication(v *CellStateIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APNotificationCellList(&v.NotificationCellList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfoList(v *s14.DAPSResponseInfoList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APDAPSResponseInfoList(v *s14.DAPSResponseInfoList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APECGIList(v *s17.ECGIList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APECGIListForRestart(v *s17.ECGIListForRestart, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APENBConfigurationUpdateAcknowledge(v *ENBConfigurationUpdateAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBConfigurationUpdateAcknowledge(v *ENBConfigurationUpdateAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBConfigurationUpdateFailure(v *ENBConfigurationUpdateFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBConfigurationUpdateFailure(v *ENBConfigurationUpdateFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBStatusTransfer(v *ENBStatusTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBStatusTransfer(v *ENBStatusTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBX2ExtTLAs(v *s15.ENBX2ExtTLAs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s15.BridgeCompareS1APENBX2ExtTLA(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABAdmittedList(v *s15.ERABAdmittedList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABAdmittedList(v *s15.ERABAdmittedList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABFailedToResumeListResumeReq(v *s15.ERABFailedToResumeListResumeReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABFailedToResumeListResumeReq(v *s15.ERABFailedToResumeListResumeReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABFailedToResumeListResumeRes(v *s15.ERABFailedToResumeListResumeRes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABFailedToResumeListResumeRes(v *s15.ERABFailedToResumeListResumeRes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABFailedtoSetupListHOReqAck(v *s16.ERABFailedtoSetupListHOReqAck, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABFailedtoSetupListHOReqAck(v *s16.ERABFailedtoSetupListHOReqAck, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABList(v *s16.ERABList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABList(v *s16.ERABList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABModifyListBearerModConf(v *s16.ERABModifyListBearerModConf, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABModifyListBearerModConf(v *s16.ERABModifyListBearerModConf, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABModifyListBearerModRes(v *s16.ERABModifyListBearerModRes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABModifyListBearerModRes(v *s16.ERABModifyListBearerModRes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABNotToBeModifiedListBearerModInd(v *s16.ERABNotToBeModifiedListBearerModInd, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABNotToBeModifiedListBearerModInd(v *s16.ERABNotToBeModifiedListBearerModInd, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABSetupListBearerSURes(v *s16.ERABSetupListBearerSURes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABSetupListBearerSURes(v *s16.ERABSetupListBearerSURes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABSetupListCtxtSURes(v *s16.ERABSetupListCtxtSURes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABSetupListCtxtSURes(v *s16.ERABSetupListCtxtSURes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCaptureS1APERABSubjecttoDataForwardingList(v *s16.ERABSubjecttoDataForwardingList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APERABSubjecttoDataForwardingList(v *s16.ERABSubjecttoDataForwardingList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompareS1APEmergencyAreaIDBroadcast(v *s22.EmergencyAreaIDBroadcast, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s22.BridgeCompareS1APEmergencyAreaIDBroadcastItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEmergencyAreaIDCancelled(v *s22.EmergencyAreaIDCancelled, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s22.BridgeCompareS1APEmergencyAreaIDCancelledItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APForbiddenLAs(v *s18.ForbiddenLAs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCompareS1APForbiddenLAsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APForbiddenTAs(v *s18.ForbiddenTAs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCompareS1APForbiddenTAsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APGUMMEIList(v *s18.GUMMEIList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCompareS1APGUMMEI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIEsECGIList(v *s18.IEsECGIList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APInterSystemMeasurementList(v *s18.InterSystemMeasurementList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCompareS1APInterSystemMeasurementItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APInterSystemMeasurementParameters(v *InterSystemMeasurementParameters, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.MeasurementDuration))
	s.Bool(v.InterSystemMeasurementList == nil)
	s21.BridgeCaptureS1APInterSystemMeasurementList(&v.InterSystemMeasurementList, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInterSystemMeasurementParameters(v *InterSystemMeasurementParameters, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.MeasurementDuration))
	s.Bool(v.InterSystemMeasurementList == nil)
	BridgeCompareS1APInterSystemMeasurementList(&v.InterSystemMeasurementList, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APIntersystemMeasurementConfiguration(v *IntersystemMeasurementConfiguration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.RSRP == nil)
		if v.RSRP != nil {
			s.Int(int64((*v.RSRP)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.RSRQ == nil)
		if v.RSRQ != nil {
			s.Int(int64((*v.RSRQ)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SINR == nil)
		if v.SINR != nil {
			s.Int(int64((*v.SINR)))
		}
		s.End(f, nil, false)
	}
	BridgeCaptureS1APInterSystemMeasurementParameters(&v.InterSystemMeasurementParameters, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APIntersystemMeasurementConfiguration(v *IntersystemMeasurementConfiguration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.RSRP == nil)
		if v.RSRP != nil {
			s.Int(int64((*v.RSRP)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.RSRQ == nil)
		if v.RSRQ != nil {
			s.Int(int64((*v.RSRQ)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SINR == nil)
		if v.SINR != nil {
			s.Int(int64((*v.SINR)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	BridgeCompareS1APInterSystemMeasurementParameters(&v.InterSystemMeasurementParameters, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APLastVisitedPSCellList(v *s20.LastVisitedPSCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCompareS1APLastVisitedPSCellInformation(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APLoggedMBSFNMDT(v *LoggedMBSFNMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APLoggingInterval(&v.LoggingInterval, s)
	s00.BridgeCaptureS1APLoggingDuration(&v.LoggingDuration, s)
	s.Bool(v.MBSFNResultToLog == nil)
	s21.BridgeCaptureS1APMBSFNResultToLog(&v.MBSFNResultToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLoggedMBSFNMDT(v *LoggedMBSFNMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APLoggingInterval(&v.LoggingInterval, s)
	s02.BridgeCompareS1APLoggingDuration(&v.LoggingDuration, s)
	s.Bool(v.MBSFNResultToLog == nil)
	BridgeCompareS1APMBSFNResultToLog(&v.MBSFNResultToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APMBSFNResultToLog(v *s19.MBSFNResultToLog, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s19.BridgeCompareS1APMBSFNResultToLogInfo(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APMDTModeExtensionIEIEValue(v *MDTModeExtensionIEIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(197):
			{
				f := s.Begin()
				s.Bool(v.rowLoggedMBSFNMDT == nil)
				if v.rowLoggedMBSFNMDT != nil {
					BridgeCaptureS1APLoggedMBSFNMDT(v.rowLoggedMBSFNMDT, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MDTModeExtensionIEIEValue) captureSemantics(s aper.SemanticCapture) MDTModeExtensionIEIEValue {
	BridgeCaptureS1APMDTModeExtensionIEIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMDTModeExtensionIEIEValue(v *MDTModeExtensionIEIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(197):
			{
				f := s.Begin()
				s.Bool(v.rowLoggedMBSFNMDT == nil)
				if v.rowLoggedMBSFNMDT != nil {
					BridgeCompareS1APLoggedMBSFNMDT(v.rowLoggedMBSFNMDT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MDTModeExtensionIEIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMDTModeExtensionIEIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMultiCellLoadReportingRequest(v *MultiCellLoadReportingRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APRequestedCellList(&v.RequestedCellList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMultiCellLoadReportingRequest(v *MultiCellLoadReportingRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APRequestedCellList(&v.RequestedCellList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APMultiCellLoadReportingResponse(v *s19.MultiCellLoadReportingResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s19.BridgeCompareS1APMultiCellLoadReportingResponseItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNotificationCellList(v *s19.NotificationCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s19.BridgeCompareS1APNotificationCellListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPC5QoSFlowList(v *s20.PC5QoSFlowList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCompareS1APPC5QoSFlowItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APPC5QoSParameters(v *PC5QoSParameters, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APPC5QoSFlowList(&v.Pc5QoSFlowList, s)
	{
		f := s.Begin()
		s.Bool(v.Pc5LinkAggregatedBitRates == nil)
		if v.Pc5LinkAggregatedBitRates != nil {
			s00.BridgeCaptureS1APBitRate(v.Pc5LinkAggregatedBitRates, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPC5QoSParameters(v *PC5QoSParameters, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APPC5QoSFlowList(&v.Pc5QoSFlowList, s)
	{
		f := s.Begin()
		s.Bool(v.Pc5LinkAggregatedBitRates == nil)
		if v.Pc5LinkAggregatedBitRates != nil {
			s02.BridgeCompareS1APBitRate(v.Pc5LinkAggregatedBitRates, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APPWSfailedECGIList(v *s20.PWSfailedECGIList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRATRestrictions(v *s20.RATRestrictions, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCompareS1APRATRestrictionsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APReportingCellList(v *s20.ReportingCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCompareS1APReportingCellListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRequestedCellList(v *s20.RequestedCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCompareS1APIRATCellID(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSONtransferRequestContainer(v *SONtransferRequestContainer, s *aper.SemanticCapture) {
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
	case s00.SONtransferRequestContainerChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceMultiCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.MultiCellLoadReporting == nil)
			if v.MultiCellLoadReporting != nil {
				BridgeCaptureS1APMultiCellLoadReportingRequest(v.MultiCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s17.BridgeCaptureS1APEventTriggeredCellLoadReportingRequest(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
				s22.BridgeCaptureS1APHOReport(v.HOReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s22.BridgeCaptureS1APCellActivationRequest(v.EutranCellActivation, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
				BridgeCaptureS1APCellStateIndication(v.EnergySavingsIndication, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
				s20.BridgeCaptureS1APFailureEventReport(v.FailureEventReporting, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APSONtransferRequestContainer(v *SONtransferRequestContainer, s *aper.SemanticComparison) {
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
	case s00.SONtransferRequestContainerChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceMultiCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.MultiCellLoadReporting == nil)
			if v.MultiCellLoadReporting != nil {
				BridgeCompareS1APMultiCellLoadReportingRequest(v.MultiCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s17.BridgeCompareS1APEventTriggeredCellLoadReportingRequest(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
				s22.BridgeCompareS1APHOReport(v.HOReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s22.BridgeCompareS1APCellActivationRequest(v.EutranCellActivation, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
				BridgeCompareS1APCellStateIndication(v.EnergySavingsIndication, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
				s20.BridgeCompareS1APFailureEventReport(v.FailureEventReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APSONtransferResponseContainer(v *SONtransferResponseContainer, s *aper.SemanticCapture) {
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
	case s00.SONtransferResponseContainerChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
				s17.BridgeCaptureS1APCellLoadReportingResponse(v.CellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceMultiCellLoadReporting:
		s21.BridgeCaptureS1APMultiCellLoadReportingResponse(&v.MultiCellLoadReporting, s)
	case s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s18.BridgeCaptureS1APEventTriggeredCellLoadReportingResponse(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s21.BridgeCaptureS1APCellActivationResponse(v.EutranCellActivation, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APSONtransferResponseContainer(v *SONtransferResponseContainer, s *aper.SemanticComparison) {
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
	case s00.SONtransferResponseContainerChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
				s17.BridgeCompareS1APCellLoadReportingResponse(v.CellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceMultiCellLoadReporting:
		BridgeCompareS1APMultiCellLoadReportingResponse(&v.MultiCellLoadReporting, s)
	case s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s18.BridgeCompareS1APEventTriggeredCellLoadReportingResponse(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s21.BridgeCompareS1APCellActivationResponse(v.EutranCellActivation, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APUERadioCapabilityMatchResponseIEValue(v *UERadioCapabilityMatchResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(169):
			{
				f := s.Begin()
				s.Bool(v.rowVoiceSupportMatchIndicator == nil)
				if v.rowVoiceSupportMatchIndicator != nil {
					s00.BridgeCaptureS1APVoiceSupportMatchIndicator(v.rowVoiceSupportMatchIndicator, s)
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
func (v UERadioCapabilityMatchResponseIEValue) captureSemantics(s aper.SemanticCapture) UERadioCapabilityMatchResponseIEValue {
	BridgeCaptureS1APUERadioCapabilityMatchResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUERadioCapabilityMatchResponseIEValue(v *UERadioCapabilityMatchResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(169):
			{
				f := s.Begin()
				s.Bool(v.rowVoiceSupportMatchIndicator == nil)
				if v.rowVoiceSupportMatchIndicator != nil {
					s07.BridgeCompareS1APVoiceSupportMatchIndicator(v.rowVoiceSupportMatchIndicator, s)
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
func (v UERadioCapabilityMatchResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUERadioCapabilityMatchResponseIEValue(&v, &s)
	return s
}

// IntersystemMeasurementConfiguration represents the ASN.1 type IntersystemMeasurementConfiguration (SEQUENCE).
type IntersystemMeasurementConfiguration struct {
	replay                           aper.Snapshot
	stream                           aper.WireSpan
	received                         bool
	withoutReplay                    bool
	receivedAbsolute                 bool
	receivedBytes                    aper.WireSpan
	receivedLocation                 aper.Location
	RSRP                             *int64                                                    `asn1:"tag:0,context,implicit,optional" json:"RSRP,omitempty"`
	RSRQ                             *int64                                                    `asn1:"tag:1,context,implicit,optional" json:"RSRQ,omitempty"`
	SINR                             *int64                                                    `asn1:"tag:2,context,implicit,optional" json:"SINR,omitempty"`
	InterSystemMeasurementParameters InterSystemMeasurementParameters                          `asn1:"tag:3,context,implicit"`
	IEExtensions                     s09.IntersystemMeasurementConfigurationExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                bool                                                      `asn1:"-" json:"-"`
	extCount                         int64                                                     `asn1:"-" json:"-"`
	extPresent                       []bool                                                    `asn1:"-" json:"-"`
	extData                          [][]byte                                                  `asn1:"-" json:"-"`
	perPadding                       aper.FinalPadding                                         `asn1:"-" json:"-"`
	perExtPadding                    []aper.CompletePadding                                    `asn1:"-" json:"-"`
	extOrigin                        []aper.OpaqueOrigin
	extWire                          []aper.WireSpan
}

// InterSystemMeasurementParameters represents the ASN.1 type InterSystemMeasurementParameters (SEQUENCE).
type InterSystemMeasurementParameters struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	MeasurementDuration             int64                                                  `asn1:"tag:0,context,implicit"`
	InterSystemMeasurementList      s18.InterSystemMeasurementList                         `asn1:"tag:1,context,implicit,optional" json:"InterSystemMeasurementList,omitzero"`
	interSystemMeasurementListIndef bool                                                   `asn1:"-" json:"-"`
	IEExtensions                    s09.InterSystemMeasurementParametersExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef               bool                                                   `asn1:"-" json:"-"`
	extCount                        int64                                                  `asn1:"-" json:"-"`
	extPresent                      []bool                                                 `asn1:"-" json:"-"`
	extData                         [][]byte                                               `asn1:"-" json:"-"`
	perPadding                      aper.FinalPadding                                      `asn1:"-" json:"-"`
	perExtPadding                   []aper.CompletePadding                                 `asn1:"-" json:"-"`
	extOrigin                       []aper.OpaqueOrigin
	extWire                         []aper.WireSpan
}

// LoggedMBSFNMDT represents the ASN.1 type LoggedMBSFNMDT (SEQUENCE).
type LoggedMBSFNMDT struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	LoggingInterval       s00.LoggingInterval                  `asn1:"tag:0,context,implicit"`
	LoggingDuration       s00.LoggingDuration                  `asn1:"tag:1,context,implicit"`
	MBSFNResultToLog      s19.MBSFNResultToLog                 `asn1:"tag:2,context,implicit,optional" json:"MBSFNResultToLog,omitzero"`
	mBSFNResultToLogIndef bool                                 `asn1:"-" json:"-"`
	IEExtensions          s09.LoggedMBSFNMDTExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                 `asn1:"-" json:"-"`
	extCount              int64                                `asn1:"-" json:"-"`
	extPresent            []bool                               `asn1:"-" json:"-"`
	extData               [][]byte                             `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// PC5QoSParameters represents the ASN.1 type PC5QoSParameters (SEQUENCE).
type PC5QoSParameters struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	Pc5QoSFlowList            s20.PC5QoSFlowList                     `asn1:"tag:0,context,implicit"`
	pc5QoSFlowListIndef       bool                                   `asn1:"-" json:"-"`
	Pc5LinkAggregatedBitRates *s00.BitRate                           `asn1:"tag:1,context,implicit,optional" json:"Pc5LinkAggregatedBitRates,omitempty"`
	IEExtensions              s10.PC5QoSParametersExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                   `asn1:"-" json:"-"`
	extCount                  int64                                  `asn1:"-" json:"-"`
	extPresent                []bool                                 `asn1:"-" json:"-"`
	extData                   [][]byte                               `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// MarshalAPER encodes IntersystemMeasurementConfiguration to APER format.
func (v *IntersystemMeasurementConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *IntersystemMeasurementConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.RSRP != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.RSRQ != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SINR != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.RSRP != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.RSRP), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding rSRP: %w", err)
		}
	}
	if v.RSRQ != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.RSRQ), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding rSRQ: %w", err)
		}
	}
	if v.SINR != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.SINR), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sINR: %w", err)
		}
	}
	if err := v.InterSystemMeasurementParameters.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding interSystemMeasurementParameters: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes IntersystemMeasurementConfiguration from APER format.
func (v *IntersystemMeasurementConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes IntersystemMeasurementConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *IntersystemMeasurementConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "IntersystemMeasurementConfiguration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "IntersystemMeasurementConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "IntersystemMeasurementConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "IntersystemMeasurementConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *IntersystemMeasurementConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = IntersystemMeasurementConfiguration{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_rsrp, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_rsrq, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sinr, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_rsrp {
		val_rsrp, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "RSRP")
		}
		if err := aper.ChargeValue(bb, val_rsrp); err != nil {
			return err
		}
		v.RSRP = (*int64)(bb.OwnInt64(int64(val_rsrp)))

	}
	if opt_rsrq {
		val_rsrq, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "RSRQ")
		}
		if err := aper.ChargeValue(bb, val_rsrq); err != nil {
			return err
		}
		v.RSRQ = (*int64)(bb.OwnInt64(int64(val_rsrq)))

	}
	if opt_sinr {
		val_sinr, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SINR")
		}
		if err := aper.ChargeValue(bb, val_sinr); err != nil {
			return err
		}
		v.SINR = (*int64)(bb.OwnInt64(int64(val_sinr)))

	}
	toleranceMark_intersystemmeasurementparameters := bb.EnterComponent("InterSystemMeasurementParameters")
	if err := v.InterSystemMeasurementParameters.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementParameters")
	}
	bb.LeaveComponent(toleranceMark_intersystemmeasurementparameters)
	if opt_ieextensions {
		tmp_ieextensions := make(s09.IntersystemMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.IntersystemMeasurementConfigurationExtIEsExtField
				if err := s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes InterSystemMeasurementParameters to APER format.
func (v *InterSystemMeasurementParameters) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *InterSystemMeasurementParameters) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.InterSystemMeasurementList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.MeasurementDuration), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(100), false); err != nil {
		return fmt.Errorf("encoding measurementDuration: %w", err)
	}
	if v.InterSystemMeasurementList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.InterSystemMeasurementList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_intersystemmeasurementlist, fragmentLength_intersystemmeasurementlist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_intersystemmeasurementlist < 0 || fragmentOffset_intersystemmeasurementlist > int64(len(v.InterSystemMeasurementList)) || fragmentLength_intersystemmeasurementlist < 0 || fragmentLength_intersystemmeasurementlist > int64(len(v.InterSystemMeasurementList[fragmentOffset_intersystemmeasurementlist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.InterSystemMeasurementList[fragmentOffset_intersystemmeasurementlist : fragmentOffset_intersystemmeasurementlist+fragmentLength_intersystemmeasurementlist] {
				if err := s18.BridgeInterSystemMeasurementItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding interSystemMeasurementList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding interSystemMeasurementList: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes InterSystemMeasurementParameters from APER format.
func (v *InterSystemMeasurementParameters) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterSystemMeasurementParameters with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterSystemMeasurementParameters) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementParameters")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementParameters")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterSystemMeasurementParameters")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementParameters")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *InterSystemMeasurementParameters) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterSystemMeasurementParameters{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_intersystemmeasurementlist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_measurementduration, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(100), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementDuration")
	}
	v.MeasurementDuration = val_measurementduration
	if opt_intersystemmeasurementlist {
		tmp_intersystemmeasurementlist := make(s18.InterSystemMeasurementList, 0)
		_, errCollection_intersystemmeasurementlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_intersystemmeasurementlist, fragmentLength_intersystemmeasurementlist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_intersystemmeasurementlist < 0 || fragmentLength_intersystemmeasurementlist < 0 || fragmentLength_intersystemmeasurementlist > int64(^uint(0)>>1) || fragmentOffset_intersystemmeasurementlist > int64(^uint(0)>>1)-fragmentLength_intersystemmeasurementlist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_intersystemmeasurementlist; i++ {
				var elem s18.InterSystemMeasurementItem
				if err := s18.BridgeInterSystemMeasurementItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("InterSystemMeasurementList[%d]", fragmentOffset_intersystemmeasurementlist+i))
				}
				if next, err := aper.AppendValues(bb, tmp_intersystemmeasurementlist, elem); err != nil {
					return err
				} else {
					tmp_intersystemmeasurementlist = next
				}
			}
			return nil
		})
		if errCollection_intersystemmeasurementlist != nil {
			return runtime.WrapDecodePath(errCollection_intersystemmeasurementlist, "InterSystemMeasurementList")
		}
		v.InterSystemMeasurementList = tmp_intersystemmeasurementlist
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s09.InterSystemMeasurementParametersExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.InterSystemMeasurementParametersExtIEsExtField
				if err := s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes LoggedMBSFNMDT to APER format.
func (v *LoggedMBSFNMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LoggedMBSFNMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.MBSFNResultToLog != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.LoggingInterval), 8, false); err != nil {
		return fmt.Errorf("encoding loggingInterval: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.LoggingDuration), 6, false); err != nil {
		return fmt.Errorf("encoding loggingDuration: %w", err)
	}
	if v.MBSFNResultToLog != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.MBSFNResultToLog)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnresulttolog, fragmentLength_mbsfnresulttolog int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_mbsfnresulttolog < 0 || fragmentOffset_mbsfnresulttolog > int64(len(v.MBSFNResultToLog)) || fragmentLength_mbsfnresulttolog < 0 || fragmentLength_mbsfnresulttolog > int64(len(v.MBSFNResultToLog[fragmentOffset_mbsfnresulttolog:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.MBSFNResultToLog[fragmentOffset_mbsfnresulttolog : fragmentOffset_mbsfnresulttolog+fragmentLength_mbsfnresulttolog] {
				if err := s19.BridgeMBSFNResultToLogInfoMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding mBSFN-ResultToLog element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding mBSFN-ResultToLog: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LoggedMBSFNMDT from APER format.
func (v *LoggedMBSFNMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LoggedMBSFNMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LoggedMBSFNMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMBSFNMDT")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMBSFNMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "LoggedMBSFNMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggedMBSFNMDT")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LoggedMBSFNMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LoggedMBSFNMDT{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_mbsfnresulttolog, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
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
	if opt_mbsfnresulttolog {
		toleranceMark_mbsfnresulttolog := bb.EnterComponent("MBSFNResultToLog")
		tmp_mbsfnresulttolog := make(s19.MBSFNResultToLog, 0)
		_, errCollection_mbsfnresulttolog := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnresulttolog, fragmentLength_mbsfnresulttolog int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_mbsfnresulttolog < 0 || fragmentLength_mbsfnresulttolog < 0 || fragmentLength_mbsfnresulttolog > int64(^uint(0)>>1) || fragmentOffset_mbsfnresulttolog > int64(^uint(0)>>1)-fragmentLength_mbsfnresulttolog {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_mbsfnresulttolog; i++ {
				var elem s19.MBSFNResultToLogInfo
				elementMark := bb.EnterIndex(fragmentOffset_mbsfnresulttolog + i)
				if err := s19.BridgeMBSFNResultToLogInfoMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MBSFNResultToLog[%d]", fragmentOffset_mbsfnresulttolog+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_mbsfnresulttolog, elem); err != nil {
					return err
				} else {
					tmp_mbsfnresulttolog = next
				}
			}
			return nil
		})
		if errCollection_mbsfnresulttolog != nil {
			return runtime.WrapDecodePath(errCollection_mbsfnresulttolog, "MBSFNResultToLog")
		}
		v.MBSFNResultToLog = tmp_mbsfnresulttolog
		bb.LeaveComponent(toleranceMark_mbsfnresulttolog)
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s09.LoggedMBSFNMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.LoggedMBSFNMDTExtIEsExtField
				if err := s09.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes PC5QoSParameters to APER format.
func (v *PC5QoSParameters) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PC5QoSParameters) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.Pc5LinkAggregatedBitRates != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.Pc5QoSFlowList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_pc5qosflowlist, fragmentLength_pc5qosflowlist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_pc5qosflowlist < 0 || fragmentOffset_pc5qosflowlist > int64(len(v.Pc5QoSFlowList)) || fragmentLength_pc5qosflowlist < 0 || fragmentLength_pc5qosflowlist > int64(len(v.Pc5QoSFlowList[fragmentOffset_pc5qosflowlist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Pc5QoSFlowList[fragmentOffset_pc5qosflowlist : fragmentOffset_pc5qosflowlist+fragmentLength_pc5qosflowlist] {
			if err := s20.BridgePC5QoSFlowItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding pc5QoSFlowList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding pc5QoSFlowList: %w", err)
	}
	if v.Pc5LinkAggregatedBitRates != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.Pc5LinkAggregatedBitRates), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
			return fmt.Errorf("encoding pc5LinkAggregatedBitRates: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PC5QoSParameters from APER format.
func (v *PC5QoSParameters) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PC5QoSParameters with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PC5QoSParameters) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSParameters")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSParameters")
	}
	padding, err := aper.CaptureFinalBits(bb, "PC5QoSParameters")
	if err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSParameters")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PC5QoSParameters) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5QoSParameters{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_pc5linkaggregatedbitrates, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_pc5qosflowlist := bb.EnterComponent("Pc5QoSFlowList")
	v.Pc5QoSFlowList = make(s20.PC5QoSFlowList, 0)
	_, errCollection_pc5qosflowlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_pc5qosflowlist, fragmentLength_pc5qosflowlist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_pc5qosflowlist < 0 || fragmentLength_pc5qosflowlist < 0 || fragmentLength_pc5qosflowlist > int64(^uint(0)>>1) || fragmentOffset_pc5qosflowlist > int64(^uint(0)>>1)-fragmentLength_pc5qosflowlist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_pc5qosflowlist; i++ {
			var elem s20.PC5QoSFlowItem
			elementMark := bb.EnterIndex(fragmentOffset_pc5qosflowlist + i)
			if err := s20.BridgePC5QoSFlowItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Pc5QoSFlowList[%d]", fragmentOffset_pc5qosflowlist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Pc5QoSFlowList, elem); err != nil {
				return err
			} else {
				v.Pc5QoSFlowList = next
			}
		}
		return nil
	})
	if errCollection_pc5qosflowlist != nil {
		return runtime.WrapDecodePath(errCollection_pc5qosflowlist, "Pc5QoSFlowList")
	}
	bb.LeaveComponent(toleranceMark_pc5qosflowlist)
	if opt_pc5linkaggregatedbitrates {
		val_pc5linkaggregatedbitrates, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "Pc5LinkAggregatedBitRates")
		}
		tmp_pc5linkaggregatedbitrates := s00.BitRate(val_pc5linkaggregatedbitrates)
		if err := aper.ChargeValue(bb, tmp_pc5linkaggregatedbitrates); err != nil {
			return err
		}
		v.Pc5LinkAggregatedBitRates = (*s00.BitRate)(bb.OwnInt64(int64(tmp_pc5linkaggregatedbitrates)))

	}
	if opt_ieextensions {
		tmp_ieextensions := make(s10.PC5QoSParametersExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.PC5QoSParametersExtIEsExtField
				if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *InterSystemMeasurementParameters) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterSystemMeasurementParameters", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InterSystemMeasurementParameters", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterSystemMeasurementParameters) WithoutReplay() InterSystemMeasurementParameters {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InterSystemMeasurementParameters
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *IntersystemMeasurementConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "IntersystemMeasurementConfiguration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "IntersystemMeasurementConfiguration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v IntersystemMeasurementConfiguration) WithoutReplay() IntersystemMeasurementConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero IntersystemMeasurementConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LoggedMBSFNMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LoggedMBSFNMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LoggedMBSFNMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LoggedMBSFNMDT) WithoutReplay() LoggedMBSFNMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LoggedMBSFNMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PC5QoSParameters) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PC5QoSParameters", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PC5QoSParameters", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PC5QoSParameters) WithoutReplay() PC5QoSParameters {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PC5QoSParameters
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *InterSystemMeasurementParameters) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *InterSystemMeasurementParameters) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InterSystemMeasurementParameters.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InterSystemMeasurementParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *InterSystemMeasurementParameters) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InterSystemMeasurementParameters.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InterSystemMeasurementParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *IntersystemMeasurementConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *IntersystemMeasurementConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("IntersystemMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("IntersystemMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *IntersystemMeasurementConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("IntersystemMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("IntersystemMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *LoggedMBSFNMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LoggedMBSFNMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LoggedMBSFNMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LoggedMBSFNMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LoggedMBSFNMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LoggedMBSFNMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LoggedMBSFNMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PC5QoSParameters) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PC5QoSParameters) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PC5QoSParameters.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PC5QoSParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PC5QoSParameters) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PC5QoSParameters.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PC5QoSParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *InterSystemMeasurementParameters) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InterSystemMeasurementParameters")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InterSystemMeasurementParameters) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterSystemMeasurementParameters")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInterSystemMeasurementParameters(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InterSystemMeasurementParameters")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InterSystemMeasurementParameters")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InterSystemMeasurementParameters) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InterSystemMeasurementParameters")
}
func (v *InterSystemMeasurementParameters) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InterSystemMeasurementParameters")
}
func (v *InterSystemMeasurementParameters) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInterSystemMeasurementParameters(v, &s)
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
func (v *InterSystemMeasurementParameters) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InterSystemMeasurementParameters) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *IntersystemMeasurementConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "IntersystemMeasurementConfiguration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *IntersystemMeasurementConfiguration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "IntersystemMeasurementConfiguration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APIntersystemMeasurementConfiguration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "IntersystemMeasurementConfiguration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "IntersystemMeasurementConfiguration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *IntersystemMeasurementConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "IntersystemMeasurementConfiguration")
}
func (v *IntersystemMeasurementConfiguration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "IntersystemMeasurementConfiguration")
}
func (v *IntersystemMeasurementConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APIntersystemMeasurementConfiguration(v, &s)
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
func (v *IntersystemMeasurementConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *IntersystemMeasurementConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LoggedMBSFNMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LoggedMBSFNMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LoggedMBSFNMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LoggedMBSFNMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLoggedMBSFNMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LoggedMBSFNMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LoggedMBSFNMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LoggedMBSFNMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LoggedMBSFNMDT")
}
func (v *LoggedMBSFNMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LoggedMBSFNMDT")
}
func (v *LoggedMBSFNMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLoggedMBSFNMDT(v, &s)
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
func (v *LoggedMBSFNMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LoggedMBSFNMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PC5QoSParameters) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PC5QoSParameters")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PC5QoSParameters) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PC5QoSParameters")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPC5QoSParameters(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PC5QoSParameters")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PC5QoSParameters")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PC5QoSParameters) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PC5QoSParameters")
}
func (v *PC5QoSParameters) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PC5QoSParameters")
}
func (v *PC5QoSParameters) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPC5QoSParameters(v, &s)
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
func (v *PC5QoSParameters) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PC5QoSParameters) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *InterSystemMeasurementParameters) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterSystemMeasurementParameters")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InterSystemMeasurementParameters
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInterSystemMeasurementParameters(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InterSystemMeasurementParameters{}
		return report, aper.OperationError(err, "InterSystemMeasurementParameters")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterSystemMeasurementParameters")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *IntersystemMeasurementConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "IntersystemMeasurementConfiguration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded IntersystemMeasurementConfiguration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APIntersystemMeasurementConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = IntersystemMeasurementConfiguration{}
		return report, aper.OperationError(err, "IntersystemMeasurementConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "IntersystemMeasurementConfiguration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LoggedMBSFNMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LoggedMBSFNMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LoggedMBSFNMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLoggedMBSFNMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LoggedMBSFNMDT{}
		return report, aper.OperationError(err, "LoggedMBSFNMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LoggedMBSFNMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PC5QoSParameters) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PC5QoSParameters")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PC5QoSParameters
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPC5QoSParameters(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PC5QoSParameters{}
		return report, aper.OperationError(err, "PC5QoSParameters")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PC5QoSParameters")
}

// ENBConfigurationUpdateAcknowledge represents the ASN.1 type ENBConfigurationUpdateAcknowledge (SEQUENCE).
type ENBConfigurationUpdateAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s22.ENBConfigurationUpdateAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                             `asn1:"-" json:"-"`
	extCount         int64                                            `asn1:"-" json:"-"`
	extPresent       []bool                                           `asn1:"-" json:"-"`
	extData          [][]byte                                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENBConfigurationUpdateFailure represents the ASN.1 type ENBConfigurationUpdateFailure (SEQUENCE).
type ENBConfigurationUpdateFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s22.ENBConfigurationUpdateFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENBStatusTransfer represents the ASN.1 type ENBStatusTransfer (SEQUENCE).
type ENBStatusTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s21.ENBStatusTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ENBConfigurationUpdateAcknowledge to APER format.
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBConfigurationUpdateAcknowledge from APER format.
func (v *ENBConfigurationUpdateAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBConfigurationUpdateAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBConfigurationUpdateAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBConfigurationUpdateAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdateAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s22.ENBConfigurationUpdateAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.ENBConfigurationUpdateAcknowledgeIEField
			if err := s22.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
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

// MarshalAPER encodes ENBConfigurationUpdateFailure to APER format.
func (v *ENBConfigurationUpdateFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBConfigurationUpdateFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s22.BridgeENBConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBConfigurationUpdateFailure from APER format.
func (v *ENBConfigurationUpdateFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBConfigurationUpdateFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBConfigurationUpdateFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailure")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBConfigurationUpdateFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdateFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s22.ENBConfigurationUpdateFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.ENBConfigurationUpdateFailureIEField
			if err := s22.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
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

// MarshalAPER encodes ENBStatusTransfer to APER format.
func (v *ENBStatusTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBStatusTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s21.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBStatusTransfer from APER format.
func (v *ENBStatusTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBStatusTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBStatusTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransfer")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBStatusTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBStatusTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBStatusTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s21.ENBStatusTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s21.ENBStatusTransferIEField
			if err := s21.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
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
func (v *ENBConfigurationUpdateAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBConfigurationUpdateAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBConfigurationUpdateAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBConfigurationUpdateAcknowledge) WithoutReplay() ENBConfigurationUpdateAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBConfigurationUpdateAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBConfigurationUpdateFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBConfigurationUpdateFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBConfigurationUpdateFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBConfigurationUpdateFailure) WithoutReplay() ENBConfigurationUpdateFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBConfigurationUpdateFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBStatusTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBStatusTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBStatusTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBStatusTransfer) WithoutReplay() ENBStatusTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBStatusTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBConfigurationUpdateAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBConfigurationUpdateAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBConfigurationUpdateAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENBConfigurationUpdateFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBConfigurationUpdateFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBConfigurationUpdateFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENBStatusTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBStatusTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBStatusTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBConfigurationUpdateAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBConfigurationUpdateAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBConfigurationUpdateAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBConfigurationUpdateAcknowledge(v, &s)
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
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBConfigurationUpdateFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBConfigurationUpdateFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBConfigurationUpdateFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBConfigurationUpdateFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBConfigurationUpdateFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBConfigurationUpdateFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBConfigurationUpdateFailure")
}
func (v *ENBConfigurationUpdateFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBConfigurationUpdateFailure")
}
func (v *ENBConfigurationUpdateFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBConfigurationUpdateFailure(v, &s)
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
func (v *ENBConfigurationUpdateFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBConfigurationUpdateFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBStatusTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBStatusTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBStatusTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBStatusTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBStatusTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBStatusTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBStatusTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBStatusTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBStatusTransfer")
}
func (v *ENBStatusTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBStatusTransfer")
}
func (v *ENBStatusTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBStatusTransfer(v, &s)
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
func (v *ENBStatusTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBStatusTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBConfigurationUpdateAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBConfigurationUpdateAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBConfigurationUpdateAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBConfigurationUpdateAcknowledge{}
		return report, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBConfigurationUpdateAcknowledge")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBConfigurationUpdateFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBConfigurationUpdateFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBConfigurationUpdateFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBConfigurationUpdateFailure{}
		return report, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBConfigurationUpdateFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBStatusTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBStatusTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBStatusTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBStatusTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBStatusTransfer{}
		return report, aper.OperationError(err, "ENBStatusTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBStatusTransfer")
}

// SONtransferRequestContainer represents the ASN.1 CHOICE type SONtransferRequestContainer.
type SONtransferRequestContainer struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	Choice                          int
	perPadding                      aper.CompletePadding                        `json:"-"`
	perOpenTypePadding              aper.CompletePadding                        `json:"-"`
	UnknownExtension                *aper.ChoiceExtension                       `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *struct{}                                   `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          *MultiCellLoadReportingRequest              `json:"MultiCellLoadReporting,omitempty"`
	EventTriggeredCellLoadReporting *s17.EventTriggeredCellLoadReportingRequest `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *s22.HOReport                               `json:"HOReporting,omitempty"`
	EutranCellActivation            *s22.CellActivationRequest                  `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *CellStateIndication                        `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *s20.FailureEventReport                     `json:"FailureEventReporting,omitempty"`
}

// SONtransferResponseContainer represents the ASN.1 CHOICE type SONtransferResponseContainer.
type SONtransferResponseContainer struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	Choice                          int
	perPadding                      aper.CompletePadding                         `json:"-"`
	perOpenTypePadding              aper.CompletePadding                         `json:"-"`
	UnknownExtension                *aper.ChoiceExtension                        `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *s17.CellLoadReportingResponse               `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          s19.MultiCellLoadReportingResponse           `json:"MultiCellLoadReporting,omitzero"`
	EventTriggeredCellLoadReporting *s18.EventTriggeredCellLoadReportingResponse `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *struct{}                                    `json:"HOReporting,omitempty"`
	EutranCellActivation            *s21.CellActivationResponse                  `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *struct{}                                    `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *struct{}                                    `json:"FailureEventReporting,omitempty"`
}

// MultiCellLoadReportingRequest represents the ASN.1 type MultiCellLoadReportingRequest (SEQUENCE).
type MultiCellLoadReportingRequest struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	RequestedCellList      s20.RequestedCellList  `asn1:"tag:0,context,implicit"`
	requestedCellListIndef bool                   `asn1:"-" json:"-"`
	extCount               int64                  `asn1:"-" json:"-"`
	extPresent             []bool                 `asn1:"-" json:"-"`
	extData                [][]byte               `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// CellStateIndication represents the ASN.1 type CellStateIndication (SEQUENCE).
type CellStateIndication struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	NotificationCellList      s19.NotificationCellList `asn1:"tag:0,context,implicit"`
	notificationCellListIndef bool                     `asn1:"-" json:"-"`
	extCount                  int64                    `asn1:"-" json:"-"`
	extPresent                []bool                   `asn1:"-" json:"-"`
	extData                   [][]byte                 `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding        `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding   `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// MarshalAPER encodes SONtransferRequestContainer to APER format.
func (v *SONtransferRequestContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONtransferRequestContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONtransferRequestContainer:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONtransferRequestContainer:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 6 {
			return fmt.Errorf("%s extension index %d is known to this schema", "SONtransferRequestContainer:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "SONtransferRequestContainer:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 1 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.SONtransferRequestContainerChoiceMultiCellLoadReporting:
			if v.MultiCellLoadReporting == nil {
				return fmt.Errorf("choice alternative multiCellLoadReporting is nil")
			}
			if err := v.MultiCellLoadReporting.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := s17.BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERTo(v.EventTriggeredCellLoadReporting, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceHOReporting:
			if v.HOReporting == nil {
				return fmt.Errorf("choice alternative hOReporting is nil")
			}
			if err := s22.BridgeHOReportMethodMarshalAPERTo(v.HOReporting, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding hOReporting: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := s22.BridgeCellActivationRequestMethodMarshalAPERTo(v.EutranCellActivation, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceEnergySavingsIndication:
			if v.EnergySavingsIndication == nil {
				return fmt.Errorf("choice alternative energySavingsIndication is nil")
			}
			if err := v.EnergySavingsIndication.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding energySavingsIndication: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceFailureEventReporting:
			if v.FailureEventReporting == nil {
				return fmt.Errorf("choice alternative failureEventReporting is nil")
			}
			if err := s20.BridgeFailureEventReportMethodMarshalAPERTo(v.FailureEventReporting, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding failureEventReporting: %w", err)
			}
		default:
			return fmt.Errorf("unknown SONtransferRequestContainer extension choice %d", v.Choice)
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
	switch v.Choice {
	case s00.SONtransferRequestContainerChoiceCellLoadReporting:
	default:
		return fmt.Errorf("unknown SONtransferRequestContainer choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferRequestContainer from APER format.
func (v *SONtransferRequestContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SONtransferRequestContainer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SONtransferRequestContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONtransferRequestContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONtransferRequestContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONtransferRequestContainer{}
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
		if extIdx >= 6 {
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
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(1) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 1 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.SONtransferRequestContainerChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			recoveryMark_multicellloadreporting := inner.RecoveryComponent("MultiCellLoadReporting")
			var dec_multicellloadreporting MultiCellLoadReportingRequest
			if err := dec_multicellloadreporting.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "MultiCellLoadReporting")
			}
			if err := aper.ChargeValue(inner, dec_multicellloadreporting); err != nil {
				return err
			}
			v.MultiCellLoadReporting = &dec_multicellloadreporting
			inner.LeaveComponent(recoveryMark_multicellloadreporting)
		case s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			recoveryMark_eventtriggeredcellloadreporting := inner.RecoveryComponent("EventTriggeredCellLoadReporting")
			var dec_eventtriggeredcellloadreporting s17.EventTriggeredCellLoadReportingRequest
			if err := s17.BridgeEventTriggeredCellLoadReportingRequestMethodUnmarshalAPERFrom(&dec_eventtriggeredcellloadreporting, inner); err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			if err := aper.ChargeValue(inner, dec_eventtriggeredcellloadreporting); err != nil {
				return err
			}
			v.EventTriggeredCellLoadReporting = &dec_eventtriggeredcellloadreporting
			inner.LeaveComponent(recoveryMark_eventtriggeredcellloadreporting)
		case s00.SONtransferRequestContainerChoiceHOReporting:
			extensionPath = "HOReporting"
			recoveryMark_horeporting := inner.RecoveryComponent("HOReporting")
			var dec_horeporting s22.HOReport
			if err := s22.BridgeHOReportMethodUnmarshalAPERFrom(&dec_horeporting, inner); err != nil {
				return runtime.WrapDecodePath(err, "HOReporting")
			}
			if err := aper.ChargeValue(inner, dec_horeporting); err != nil {
				return err
			}
			v.HOReporting = &dec_horeporting
			inner.LeaveComponent(recoveryMark_horeporting)
		case s00.SONtransferRequestContainerChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			recoveryMark_eutrancellactivation := inner.RecoveryComponent("EutranCellActivation")
			var dec_eutrancellactivation s22.CellActivationRequest
			if err := s22.BridgeCellActivationRequestMethodUnmarshalAPERFrom(&dec_eutrancellactivation, inner); err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			if err := aper.ChargeValue(inner, dec_eutrancellactivation); err != nil {
				return err
			}
			v.EutranCellActivation = &dec_eutrancellactivation
			inner.LeaveComponent(recoveryMark_eutrancellactivation)
		case s00.SONtransferRequestContainerChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			recoveryMark_energysavingsindication := inner.RecoveryComponent("EnergySavingsIndication")
			var dec_energysavingsindication CellStateIndication
			if err := dec_energysavingsindication.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EnergySavingsIndication")
			}
			if err := aper.ChargeValue(inner, dec_energysavingsindication); err != nil {
				return err
			}
			v.EnergySavingsIndication = &dec_energysavingsindication
			inner.LeaveComponent(recoveryMark_energysavingsindication)
		case s00.SONtransferRequestContainerChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			recoveryMark_failureeventreporting := inner.RecoveryComponent("FailureEventReporting")
			var dec_failureeventreporting s20.FailureEventReport
			if err := s20.BridgeFailureEventReportMethodUnmarshalAPERFrom(&dec_failureeventreporting, inner); err != nil {
				return runtime.WrapDecodePath(err, "FailureEventReporting")
			}
			if err := aper.ChargeValue(inner, dec_failureeventreporting); err != nil {
				return err
			}
			v.FailureEventReporting = &dec_failureeventreporting
			inner.LeaveComponent(recoveryMark_failureeventreporting)
		}
		padding, err := aper.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case s00.SONtransferRequestContainerChoiceCellLoadReporting:
		v.CellLoadReporting = new(struct{})
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes SONtransferResponseContainer to APER format.
func (v *SONtransferResponseContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONtransferResponseContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONtransferResponseContainer:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONtransferResponseContainer:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 6 {
			return fmt.Errorf("%s extension index %d is known to this schema", "SONtransferResponseContainer:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "SONtransferResponseContainer:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 1 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.SONtransferResponseContainerChoiceMultiCellLoadReporting:
			if err := aper.EncodeCollection(inner, int64(len(v.MultiCellLoadReporting)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_multicellloadreporting, fragmentLength_multicellloadreporting int64) error {
				// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
				if fragmentOffset_multicellloadreporting < 0 || fragmentOffset_multicellloadreporting > int64(len(v.MultiCellLoadReporting)) || fragmentLength_multicellloadreporting < 0 || fragmentLength_multicellloadreporting > int64(len(v.MultiCellLoadReporting[fragmentOffset_multicellloadreporting:])) {
					return fmt.Errorf("collection fragment outside value")
				}
				for _, elem := range v.MultiCellLoadReporting[fragmentOffset_multicellloadreporting : fragmentOffset_multicellloadreporting+fragmentLength_multicellloadreporting] {
					if err := s19.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERTo(&elem, inner, len(fresh) != 0 && fresh[0]); err != nil {
						return fmt.Errorf("encoding multiCellLoadReporting element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := s18.BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERTo(v.EventTriggeredCellLoadReporting, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case s00.SONtransferResponseContainerChoiceHOReporting:
		case s00.SONtransferResponseContainerChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := s21.BridgeCellActivationResponseMethodMarshalAPERTo(v.EutranCellActivation, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case s00.SONtransferResponseContainerChoiceEnergySavingsIndication:
		case s00.SONtransferResponseContainerChoiceFailureEventReporting:
		default:
			return fmt.Errorf("unknown SONtransferResponseContainer extension choice %d", v.Choice)
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
	switch v.Choice {
	case s00.SONtransferResponseContainerChoiceCellLoadReporting:
		if v.CellLoadReporting == nil {
			return fmt.Errorf("choice alternative cellLoadReporting is nil")
		}
		if err := s17.BridgeCellLoadReportingResponseMethodMarshalAPERTo(v.CellLoadReporting, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding cellLoadReporting: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONtransferResponseContainer choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferResponseContainer from APER format.
func (v *SONtransferResponseContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SONtransferResponseContainer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SONtransferResponseContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONtransferResponseContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONtransferResponseContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONtransferResponseContainer{}
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
		if extIdx >= 6 {
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
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(1) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 1 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.SONtransferResponseContainerChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			recoveryMark_multicellloadreporting := inner.RecoveryComponent("MultiCellLoadReporting")
			tmp_multicellloadreporting := make(s19.MultiCellLoadReportingResponse, 0)
			_, errCollection_multicellloadreporting := aper.DecodeCollection(inner, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_multicellloadreporting, fragmentLength_multicellloadreporting int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
				if fragmentOffset_multicellloadreporting < 0 || fragmentLength_multicellloadreporting < 0 || fragmentLength_multicellloadreporting > int64(^uint(0)>>1) || fragmentOffset_multicellloadreporting > int64(^uint(0)>>1)-fragmentLength_multicellloadreporting {
					return fmt.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_multicellloadreporting; i++ {
					var elem s19.MultiCellLoadReportingResponseItem
					elementMark := inner.RecoveryIndex(fragmentOffset_multicellloadreporting + i)
					if err := s19.BridgeMultiCellLoadReportingResponseItemMethodUnmarshalAPERFrom(&elem, inner); err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("MultiCellLoadReporting[%d]", fragmentOffset_multicellloadreporting+i))
					}
					inner.LeaveComponent(elementMark)
					if next, err := aper.AppendValues(inner, tmp_multicellloadreporting, elem); err != nil {
						return err
					} else {
						tmp_multicellloadreporting = next
					}
				}
				return nil
			})
			if errCollection_multicellloadreporting != nil {
				return runtime.WrapDecodePath(errCollection_multicellloadreporting, "MultiCellLoadReporting")
			}
			v.MultiCellLoadReporting = tmp_multicellloadreporting
			inner.LeaveComponent(recoveryMark_multicellloadreporting)
		case s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			recoveryMark_eventtriggeredcellloadreporting := inner.RecoveryComponent("EventTriggeredCellLoadReporting")
			var dec_eventtriggeredcellloadreporting s18.EventTriggeredCellLoadReportingResponse
			if err := s18.BridgeEventTriggeredCellLoadReportingResponseMethodUnmarshalAPERFrom(&dec_eventtriggeredcellloadreporting, inner); err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			if err := aper.ChargeValue(inner, dec_eventtriggeredcellloadreporting); err != nil {
				return err
			}
			v.EventTriggeredCellLoadReporting = &dec_eventtriggeredcellloadreporting
			inner.LeaveComponent(recoveryMark_eventtriggeredcellloadreporting)
		case s00.SONtransferResponseContainerChoiceHOReporting:
			extensionPath = "HOReporting"
			v.HOReporting = new(struct{})
		case s00.SONtransferResponseContainerChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			recoveryMark_eutrancellactivation := inner.RecoveryComponent("EutranCellActivation")
			var dec_eutrancellactivation s21.CellActivationResponse
			if err := s21.BridgeCellActivationResponseMethodUnmarshalAPERFrom(&dec_eutrancellactivation, inner); err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			if err := aper.ChargeValue(inner, dec_eutrancellactivation); err != nil {
				return err
			}
			v.EutranCellActivation = &dec_eutrancellactivation
			inner.LeaveComponent(recoveryMark_eutrancellactivation)
		case s00.SONtransferResponseContainerChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			v.EnergySavingsIndication = new(struct{})
		case s00.SONtransferResponseContainerChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			v.FailureEventReporting = new(struct{})
		}
		padding, err := aper.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case s00.SONtransferResponseContainerChoiceCellLoadReporting:
		toleranceMark_cellloadreporting := bb.EnterComponent("CellLoadReporting")
		var dec_cellloadreporting s17.CellLoadReportingResponse
		if err := s17.BridgeCellLoadReportingResponseMethodUnmarshalAPERFrom(&dec_cellloadreporting, bb); err != nil {
			return runtime.WrapDecodePath(err, "CellLoadReporting")
		}
		if err := aper.ChargeValue(bb, dec_cellloadreporting); err != nil {
			return err
		}
		v.CellLoadReporting = &dec_cellloadreporting
		bb.LeaveComponent(toleranceMark_cellloadreporting)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes MultiCellLoadReportingRequest to APER format.
func (v *MultiCellLoadReportingRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MultiCellLoadReportingRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.RequestedCellList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_requestedcelllist, fragmentLength_requestedcelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_requestedcelllist < 0 || fragmentOffset_requestedcelllist > int64(len(v.RequestedCellList)) || fragmentLength_requestedcelllist < 0 || fragmentLength_requestedcelllist > int64(len(v.RequestedCellList[fragmentOffset_requestedcelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.RequestedCellList[fragmentOffset_requestedcelllist : fragmentOffset_requestedcelllist+fragmentLength_requestedcelllist] {
			if err := s18.BridgeIRATCellIDMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding requestedCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding requestedCellList: %w", err)
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

// UnmarshalAPER decodes MultiCellLoadReportingRequest from APER format.
func (v *MultiCellLoadReportingRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MultiCellLoadReportingRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MultiCellLoadReportingRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "MultiCellLoadReportingRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MultiCellLoadReportingRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MultiCellLoadReportingRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.RequestedCellList = make(s20.RequestedCellList, 0)
	_, errCollection_requestedcelllist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_requestedcelllist, fragmentLength_requestedcelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_requestedcelllist < 0 || fragmentLength_requestedcelllist < 0 || fragmentLength_requestedcelllist > int64(^uint(0)>>1) || fragmentOffset_requestedcelllist > int64(^uint(0)>>1)-fragmentLength_requestedcelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_requestedcelllist; i++ {
			var elem s18.IRATCellID
			if err := s18.BridgeIRATCellIDMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("RequestedCellList[%d]", fragmentOffset_requestedcelllist+i))
			}
			if next, err := aper.AppendValues(bb, v.RequestedCellList, elem); err != nil {
				return err
			} else {
				v.RequestedCellList = next
			}
		}
		return nil
	})
	if errCollection_requestedcelllist != nil {
		return runtime.WrapDecodePath(errCollection_requestedcelllist, "RequestedCellList")
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

// MarshalAPER encodes CellStateIndication to APER format.
func (v *CellStateIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellStateIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.NotificationCellList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_notificationcelllist, fragmentLength_notificationcelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_notificationcelllist < 0 || fragmentOffset_notificationcelllist > int64(len(v.NotificationCellList)) || fragmentLength_notificationcelllist < 0 || fragmentLength_notificationcelllist > int64(len(v.NotificationCellList[fragmentOffset_notificationcelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.NotificationCellList[fragmentOffset_notificationcelllist : fragmentOffset_notificationcelllist+fragmentLength_notificationcelllist] {
			if err := s19.BridgeNotificationCellListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding notificationCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding notificationCellList: %w", err)
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

// UnmarshalAPER decodes CellStateIndication from APER format.
func (v *CellStateIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellStateIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellStateIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellStateIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CellStateIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellStateIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_notificationcelllist := bb.EnterComponent("NotificationCellList")
	v.NotificationCellList = make(s19.NotificationCellList, 0)
	_, errCollection_notificationcelllist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_notificationcelllist, fragmentLength_notificationcelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_notificationcelllist < 0 || fragmentLength_notificationcelllist < 0 || fragmentLength_notificationcelllist > int64(^uint(0)>>1) || fragmentOffset_notificationcelllist > int64(^uint(0)>>1)-fragmentLength_notificationcelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_notificationcelllist; i++ {
			var elem s19.NotificationCellListItem
			elementMark := bb.EnterIndex(fragmentOffset_notificationcelllist + i)
			if err := s19.BridgeNotificationCellListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("NotificationCellList[%d]", fragmentOffset_notificationcelllist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.NotificationCellList, elem); err != nil {
				return err
			} else {
				v.NotificationCellList = next
			}
		}
		return nil
	})
	if errCollection_notificationcelllist != nil {
		return runtime.WrapDecodePath(errCollection_notificationcelllist, "NotificationCellList")
	}
	bb.LeaveComponent(toleranceMark_notificationcelllist)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellStateIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellStateIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellStateIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellStateIndication) WithoutReplay() CellStateIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellStateIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MultiCellLoadReportingRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MultiCellLoadReportingRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MultiCellLoadReportingRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MultiCellLoadReportingRequest) WithoutReplay() MultiCellLoadReportingRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MultiCellLoadReportingRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONtransferRequestContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONtransferRequestContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONtransferRequestContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONtransferRequestContainer) WithoutReplay() SONtransferRequestContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONtransferRequestContainer
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONtransferResponseContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONtransferResponseContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONtransferResponseContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONtransferResponseContainer) WithoutReplay() SONtransferResponseContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONtransferResponseContainer
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellStateIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellStateIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellStateIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellStateIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellStateIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellStateIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellStateIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MultiCellLoadReportingRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MultiCellLoadReportingRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MultiCellLoadReportingRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MultiCellLoadReportingRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MultiCellLoadReportingRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MultiCellLoadReportingRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MultiCellLoadReportingRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellStateIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellStateIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellStateIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellStateIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellStateIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellStateIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellStateIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellStateIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellStateIndication")
}
func (v *CellStateIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellStateIndication")
}
func (v *CellStateIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellStateIndication(v, &s)
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
func (v *CellStateIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellStateIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MultiCellLoadReportingRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MultiCellLoadReportingRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MultiCellLoadReportingRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MultiCellLoadReportingRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMultiCellLoadReportingRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MultiCellLoadReportingRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MultiCellLoadReportingRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MultiCellLoadReportingRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MultiCellLoadReportingRequest")
}
func (v *MultiCellLoadReportingRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MultiCellLoadReportingRequest")
}
func (v *MultiCellLoadReportingRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMultiCellLoadReportingRequest(v, &s)
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
func (v *MultiCellLoadReportingRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MultiCellLoadReportingRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONtransferRequestContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONtransferRequestContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONtransferRequestContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONtransferRequestContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONtransferRequestContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONtransferRequestContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONtransferRequestContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONtransferRequestContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONtransferRequestContainer")
}
func (v *SONtransferRequestContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONtransferRequestContainer")
}
func (v *SONtransferRequestContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONtransferRequestContainer(v, &s)
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
func (v *SONtransferRequestContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONtransferRequestContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONtransferResponseContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONtransferResponseContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONtransferResponseContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONtransferResponseContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONtransferResponseContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONtransferResponseContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONtransferResponseContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONtransferResponseContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONtransferResponseContainer")
}
func (v *SONtransferResponseContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONtransferResponseContainer")
}
func (v *SONtransferResponseContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONtransferResponseContainer(v, &s)
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
func (v *SONtransferResponseContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONtransferResponseContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellStateIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellStateIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellStateIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellStateIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellStateIndication{}
		return report, aper.OperationError(err, "CellStateIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellStateIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MultiCellLoadReportingRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MultiCellLoadReportingRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MultiCellLoadReportingRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMultiCellLoadReportingRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MultiCellLoadReportingRequest{}
		return report, aper.OperationError(err, "MultiCellLoadReportingRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MultiCellLoadReportingRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONtransferRequestContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONtransferRequestContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONtransferRequestContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONtransferRequestContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONtransferRequestContainer{}
		return report, aper.OperationError(err, "SONtransferRequestContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONtransferRequestContainer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONtransferResponseContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONtransferResponseContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONtransferResponseContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONtransferResponseContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONtransferResponseContainer{}
		return report, aper.OperationError(err, "SONtransferResponseContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONtransferResponseContainer")
}

// NewSONtransferRequestContainerUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONtransferRequestContainerUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerUnknownExtension")
	}
	value := SONtransferRequestContainer{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerUnknownExtension")
}

// NewSONtransferResponseContainerUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONtransferResponseContainerUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerUnknownExtension")
	}
	value := SONtransferResponseContainer{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerUnknownExtension")
}

type MDTModeExtensionIEIEValue struct {
	id                s00.ProtocolIEID
	received          aper.WireSpan
	replay            aper.Snapshot
	opaque            aper.OpaqueOpenType
	isOpaque          bool
	rowLoggedMBSFNMDT *LoggedMBSFNMDT
}

func (v MDTModeExtensionIEIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(197):
		return v.rowLoggedMBSFNMDT != nil
	}
	return false
}
func (v *MDTModeExtensionIEIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MDTModeExtensionIEIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTMode-ExtensionIE"}}
}
func (MDTModeExtensionIEIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(197):
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
func (v *MDTModeExtensionIEIEValue) AsLoggedMBSFNMDT() (*LoggedMBSFNMDT, bool) {
	if v == nil || v.id != s00.ProtocolIEID(197) || v.rowLoggedMBSFNMDT == nil {
		return nil, false
	}
	return v.rowLoggedMBSFNMDT, true
}
func (v MDTModeExtensionIEIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MDTModeExtensionIEIEValue, error) {
	out := MDTModeExtensionIEIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(197):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value LoggedMBSFNMDT
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "LoggedMBSFNMDT:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LoggedMBSFNMDT")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowLoggedMBSFNMDT = &value
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
func (v MDTModeExtensionIEIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MDTModeExtensionIEIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(197):
		if v.rowLoggedMBSFNMDT == nil {
			return nil, fmt.Errorf("%s missing value", "MDTMode-ExtensionIE.id-LoggedMBSFNMDT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowLoggedMBSFNMDT.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MDTModeExtensionIEIEValue:", v.id)
	}
}

type UERadioCapabilityMatchResponseIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowMMEUES1APID                *s00.MMEUES1APID
	rowENBUES1APID                *s00.ENBUES1APID
	rowVoiceSupportMatchIndicator *s00.VoiceSupportMatchIndicator
	rowCriticalityDiagnostics     *s22.CriticalityDiagnostics
}

func (v UERadioCapabilityMatchResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(169):
		return v.rowVoiceSupportMatchIndicator != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *UERadioCapabilityMatchResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UERadioCapabilityMatchResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs"}}
}
func (UERadioCapabilityMatchResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(169):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
func (v *UERadioCapabilityMatchResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *UERadioCapabilityMatchResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *UERadioCapabilityMatchResponseIEValue) AsVoiceSupportMatchIndicator() (*s00.VoiceSupportMatchIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(169) || v.rowVoiceSupportMatchIndicator == nil {
		return nil, false
	}
	return v.rowVoiceSupportMatchIndicator, true
}
func (v *UERadioCapabilityMatchResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UERadioCapabilityMatchResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UERadioCapabilityMatchResponseIEValue, error) {
	out := UERadioCapabilityMatchResponseIEValue{id: id}
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
	case s00.ProtocolIEID(169):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "VoiceSupportMatchIndicator"})
		value := s00.VoiceSupportMatchIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "VoiceSupportMatchIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowVoiceSupportMatchIndicator = &value
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
func (v UERadioCapabilityMatchResponseIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UERadioCapabilityMatchResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityMatchResponseIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityMatchResponseIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(169):
		if v.rowVoiceSupportMatchIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityMatchResponseIEs.id-VoiceSupportMatchIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowVoiceSupportMatchIndicator), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityMatchResponseIEs.id-CriticalityDiagnostics:")
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
		return nil, fmt.Errorf("%s id %d has no value", "UERadioCapabilityMatchResponseIEValue:", v.id)
	}
}

type MDTModeExtensionIETable struct{}

func MDTModeExtensionIE() MDTModeExtensionIETable { return MDTModeExtensionIETable{} }
func (MDTModeExtensionIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTMode-ExtensionIE"}
		return sealed
	}()
}
func (MDTModeExtensionIETable) Table() s00.MDTModeExtensionIEIEValueIETable {
	return func() s00.MDTModeExtensionIEIEValueIETable {
		sealed := s00.MDTModeExtensionIEIEValueIETable{}
		*s00.BridgeMDTModeExtensionIEIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MDTModeExtensionIETable) infoLoggedMBSFNMDT() s00.FieldInfo {
	return s00.FieldInfo{Table: MDTModeExtensionIE().ID(), ID: s00.ProtocolIEID(197), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMBSFNMDT"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTMode-ExtensionIE", Row: "id-LoggedMBSFNMDT"}}}
}
func (t MDTModeExtensionIETable) LoggedMBSFNMDT() MDTModeExtensionIELoggedMBSFNMDTIEBinding {
	return MDTModeExtensionIELoggedMBSFNMDTIEBinding{info: t.infoLoggedMBSFNMDT(), codec: LoggedMBSFNMDTValueCodec{path: "LoggedMBSFNMDT",
		decode: func(data []byte, options aper.DecodeState) (LoggedMBSFNMDT, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty LoggedMBSFNMDT
				return empty, err
			}
			var zero MDTModeExtensionIEIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(197), raw)
			if err != nil {
				var empty LoggedMBSFNMDT
				return empty, err
			}
			value, ok := decoded.AsLoggedMBSFNMDT()
			if !ok {
				var empty LoggedMBSFNMDT
				return empty, fmt.Errorf("binding MDTMode-ExtensionIE.id-LoggedMBSFNMDT: no selected value")
			}
			return *value, nil
		},
		encode: func(value LoggedMBSFNMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MDTModeExtensionIEIEValue{id: s00.ProtocolIEID(197), rowLoggedMBSFNMDT: &value}).encodeFresh(fresh, budget)
		}, capture: func(v LoggedMBSFNMDT, options aper.DecodeState) (LoggedMBSFNMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APLoggedMBSFNMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v LoggedMBSFNMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APLoggedMBSFNMDT(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LoggedMBSFNMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value LoggedMBSFNMDT) MDTModeExtensionIEIEValue {
		return MDTModeExtensionIEIEValue{id: s00.ProtocolIEID(197), rowLoggedMBSFNMDT: &value}
	}, get: func(value *MDTModeExtensionIEIEValue) (*LoggedMBSFNMDT, bool) { return value.AsLoggedMBSFNMDT() }}
}
func (t MDTModeExtensionIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MDTModeExtensionIEIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MDTModeExtensionIEIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(197):
		return MDTModeExtensionIEIEField{}, aper.OperationError(fmt.Errorf("known IE id-LoggedMBSFNMDT requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MDTModeExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MDTModeExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		return MDTModeExtensionIEIEField{Id: id, Criticality: criticality, Value: MDTModeExtensionIEIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UERadioCapabilityIDMappingResponseIETable struct{}

func UERadioCapabilityIDMappingResponseIEs() UERadioCapabilityIDMappingResponseIETable {
	return UERadioCapabilityIDMappingResponseIETable{}
}
func (UERadioCapabilityIDMappingResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs"}
		return sealed
	}()
}
func (UERadioCapabilityIDMappingResponseIETable) Table() s00.UERadioCapabilityIDMappingResponseIEValueIETable {
	return func() s00.UERadioCapabilityIDMappingResponseIEValueIETable {
		sealed := s00.UERadioCapabilityIDMappingResponseIEValueIETable{}
		*s00.BridgeUERadioCapabilityIDMappingResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UERadioCapabilityIDMappingResponseIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityIDMappingResponseIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs", Row: "id-UERadioCapabilityID"}}}
}
func (t UERadioCapabilityIDMappingResponseIETable) UERadioCapabilityID() UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding {
	return UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			var zero s23.UERadioCapabilityIDMappingResponseIEValue
			decoded, err := s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodDecode(zero, s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding UERadioCapabilityIDMappingResponseIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodEncodeFresh((func() s23.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s23.UERadioCapabilityIDMappingResponseIEValue{}
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapabilityID(&sealed) = &value
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
	}(),
		inject: func(value s00.UERadioCapabilityID) s23.UERadioCapabilityIDMappingResponseIEValue {
			return func() s23.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s23.UERadioCapabilityIDMappingResponseIEValue{}
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapabilityID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s23.UERadioCapabilityIDMappingResponseIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (UERadioCapabilityIDMappingResponseIETable) infoUERadioCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityIDMappingResponseIEs().ID(), ID: s00.ProtocolIEID(74), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs", Row: "id-UERadioCapability"}}}
}
func (t UERadioCapabilityIDMappingResponseIETable) UERadioCapability() UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding {
	return UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding{info: t.infoUERadioCapability(), codec: func() s02.UERadioCapabilityValueCodec {
		sealed := s02.UERadioCapabilityValueCodec{}
		*s02.BridgeUERadioCapabilityValueCodecFieldPath(&sealed) = "UERadioCapability"
		*s02.BridgeUERadioCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			var zero s23.UERadioCapabilityIDMappingResponseIEValue
			decoded, err := s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodDecode(zero, s00.ProtocolIEID(74), raw)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			value, ok := decoded.AsUERadioCapability()
			if !ok {
				var empty s00.UERadioCapability
				return empty, fmt.Errorf("binding UERadioCapabilityIDMappingResponseIEs.id-UERadioCapability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodEncodeFresh((func() s23.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s23.UERadioCapabilityIDMappingResponseIEValue{}
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapability(&sealed) = &value
				return sealed
			}()), fresh, budget)
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
		inject: func(value s00.UERadioCapability) s23.UERadioCapabilityIDMappingResponseIEValue {
			return func() s23.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s23.UERadioCapabilityIDMappingResponseIEValue{}
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapability(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s23.UERadioCapabilityIDMappingResponseIEValue) (*s00.UERadioCapability, bool) {
			return value.AsUERadioCapability()
		}}
}
func (UERadioCapabilityIDMappingResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityIDMappingResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UERadioCapabilityIDMappingResponseIETable) CriticalityDiagnostics() s23.UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding {
	return func() s23.UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding {
		sealed := s23.UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding{}
		*s23.BridgeUERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s23.BridgeUERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s22.CriticalityDiagnosticsValueCodec {
			sealed := s22.CriticalityDiagnosticsValueCodec{}
			*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s22.CriticalityDiagnostics
					return empty, err
				}
				var zero s23.UERadioCapabilityIDMappingResponseIEValue
				decoded, err := s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodDecode(zero, s00.ProtocolIEID(58), raw)
				if err != nil {
					var empty s22.CriticalityDiagnostics
					return empty, err
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s22.CriticalityDiagnostics
					return empty, fmt.Errorf("binding UERadioCapabilityIDMappingResponseIEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodEncodeFresh((func() s23.UERadioCapabilityIDMappingResponseIEValue {
					sealed := s23.UERadioCapabilityIDMappingResponseIEValue{}
					*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
					*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
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
		*s23.BridgeUERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s22.CriticalityDiagnostics) s23.UERadioCapabilityIDMappingResponseIEValue {
			return func() s23.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s23.UERadioCapabilityIDMappingResponseIEValue{}
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s23.UERadioCapabilityIDMappingResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}
func (t UERadioCapabilityIDMappingResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s23.UERadioCapabilityIDMappingResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(314):
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(74):
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s23.UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return s23.UERadioCapabilityIDMappingResponseIEField{Id: id, Criticality: criticality, Value: func() s23.UERadioCapabilityIDMappingResponseIEValue {
			sealed := s23.UERadioCapabilityIDMappingResponseIEValue{}
			*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = id
			*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldOpaque(&sealed) = opaque
			*s23.BridgeUERadioCapabilityIDMappingResponseIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type UERadioCapabilityMatchResponseIETable struct{}

func UERadioCapabilityMatchResponseIEs() UERadioCapabilityMatchResponseIETable {
	return UERadioCapabilityMatchResponseIETable{}
}
func (UERadioCapabilityMatchResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs"}
		return sealed
	}()
}
func (UERadioCapabilityMatchResponseIETable) Table() s00.UERadioCapabilityMatchResponseIEValueIETable {
	return func() s00.UERadioCapabilityMatchResponseIEValueIETable {
		sealed := s00.UERadioCapabilityMatchResponseIEValueIETable{}
		*s00.BridgeUERadioCapabilityMatchResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UERadioCapabilityMatchResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityMatchResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t UERadioCapabilityMatchResponseIETable) MMEUES1APID() UERadioCapabilityMatchResponseMMEUES1APIDIEBinding {
	return UERadioCapabilityMatchResponseMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero UERadioCapabilityMatchResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UERadioCapabilityMatchResponseIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UERadioCapabilityMatchResponseIEValue {
			return UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UERadioCapabilityMatchResponseIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UERadioCapabilityMatchResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityMatchResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t UERadioCapabilityMatchResponseIETable) ENBUES1APID() UERadioCapabilityMatchResponseENBUES1APIDIEBinding {
	return UERadioCapabilityMatchResponseENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero UERadioCapabilityMatchResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UERadioCapabilityMatchResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UERadioCapabilityMatchResponseIEValue {
			return UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UERadioCapabilityMatchResponseIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UERadioCapabilityMatchResponseIETable) infoVoiceSupportMatchIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityMatchResponseIEs().ID(), ID: s00.ProtocolIEID(169), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "VoiceSupportMatchIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs", Row: "id-VoiceSupportMatchIndicator"}}}
}
func (t UERadioCapabilityMatchResponseIETable) VoiceSupportMatchIndicator() UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding {
	return UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding{info: t.infoVoiceSupportMatchIndicator(), codec: func() s02.VoiceSupportMatchIndicatorValueCodec {
		sealed := s02.VoiceSupportMatchIndicatorValueCodec{}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldPath(&sealed) = "VoiceSupportMatchIndicator"
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.VoiceSupportMatchIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.VoiceSupportMatchIndicator
				return empty, err
			}
			var zero UERadioCapabilityMatchResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(169), raw)
			if err != nil {
				var empty s00.VoiceSupportMatchIndicator
				return empty, err
			}
			value, ok := decoded.AsVoiceSupportMatchIndicator()
			if !ok {
				var empty s00.VoiceSupportMatchIndicator
				return empty, fmt.Errorf("binding UERadioCapabilityMatchResponseIEs.id-VoiceSupportMatchIndicator: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldEncode(&sealed) = func(value s00.VoiceSupportMatchIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(169), rowVoiceSupportMatchIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldCapture(&sealed) = func(v s00.VoiceSupportMatchIndicator, options aper.DecodeState) (s00.VoiceSupportMatchIndicator, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APVoiceSupportMatchIndicator(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldCompare(&sealed) = func(v s00.VoiceSupportMatchIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APVoiceSupportMatchIndicator(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:VoiceSupportMatchIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.VoiceSupportMatchIndicator) UERadioCapabilityMatchResponseIEValue {
			return UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(169), rowVoiceSupportMatchIndicator: &value}
		}, get: func(value *UERadioCapabilityMatchResponseIEValue) (*s00.VoiceSupportMatchIndicator, bool) {
			return value.AsVoiceSupportMatchIndicator()
		}}
}
func (UERadioCapabilityMatchResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityMatchResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UERadioCapabilityMatchResponseIETable) CriticalityDiagnostics() UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding {
	return UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero UERadioCapabilityMatchResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UERadioCapabilityMatchResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) UERadioCapabilityMatchResponseIEValue {
			return UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UERadioCapabilityMatchResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t UERadioCapabilityMatchResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UERadioCapabilityMatchResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(169):
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-VoiceSupportMatchIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return UERadioCapabilityMatchResponseIEField{Id: id, Criticality: criticality, Value: UERadioCapabilityMatchResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CellStateIndicationCodec binds the complete source value type.
func CellStateIndicationCodec() CellStateIndicationValueCodec {
	return CellStateIndicationValueCodec{path: "CellStateIndication", decode: func(data []byte, options aper.DecodeState) (CellStateIndication, error) {
		var value CellStateIndication
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellStateIndication{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellStateIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellStateIndication, options aper.DecodeState) (CellStateIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellStateIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellStateIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellStateIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellStateIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// InterSystemMeasurementParametersCodec binds the complete source value type.
func InterSystemMeasurementParametersCodec() InterSystemMeasurementParametersValueCodec {
	return InterSystemMeasurementParametersValueCodec{path: "InterSystemMeasurementParameters", decode: func(data []byte, options aper.DecodeState) (InterSystemMeasurementParameters, error) {
		var value InterSystemMeasurementParameters
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return InterSystemMeasurementParameters{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value InterSystemMeasurementParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v InterSystemMeasurementParameters, options aper.DecodeState) (InterSystemMeasurementParameters, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APInterSystemMeasurementParameters(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v InterSystemMeasurementParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APInterSystemMeasurementParameters(&v,
			&s,
		)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterSystemMeasurementParameters"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// LoggedMBSFNMDTCodec binds the complete APER value type.
func LoggedMBSFNMDTCodec() LoggedMBSFNMDTValueCodec {
	return MDTModeExtensionIE().LoggedMBSFNMDT().Codec()
}

// MultiCellLoadReportingRequestCodec binds the complete source value type.
func MultiCellLoadReportingRequestCodec() MultiCellLoadReportingRequestValueCodec {
	return MultiCellLoadReportingRequestValueCodec{path: "MultiCellLoadReportingRequest", decode: func(data []byte, options aper.DecodeState) (MultiCellLoadReportingRequest, error) {
		var value MultiCellLoadReportingRequest
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MultiCellLoadReportingRequest{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MultiCellLoadReportingRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MultiCellLoadReportingRequest, options aper.DecodeState) (MultiCellLoadReportingRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APMultiCellLoadReportingRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v MultiCellLoadReportingRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeCompareS1APMultiCellLoadReportingRequest(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MultiCellLoadReportingRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONtransferRequestContainerCodec binds the complete source value type.
func SONtransferRequestContainerCodec() SONtransferRequestContainerValueCodec {
	return SONtransferRequestContainerValueCodec{path: "SONtransferRequestContainer", decode: func(data []byte, options aper.DecodeState) (SONtransferRequestContainer, error) {
		var value SONtransferRequestContainer
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONtransferRequestContainer{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONtransferRequestContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONtransferRequestContainer, options aper.DecodeState) (SONtransferRequestContainer, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSONtransferRequestContainer(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v SONtransferRequestContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APSONtransferRequestContainer(&v, &s)
		s.End(f,

			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONtransferRequestContainer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONtransferResponseContainerCodec binds the complete source value type.
func SONtransferResponseContainerCodec() SONtransferResponseContainerValueCodec {
	return SONtransferResponseContainerValueCodec{path: "SONtransferResponseContainer", decode: func(data []byte, options aper.DecodeState) (SONtransferResponseContainer, error) {
		var value SONtransferResponseContainer
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONtransferResponseContainer{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONtransferResponseContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONtransferResponseContainer, options aper.DecodeState) (SONtransferResponseContainer, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSONtransferResponseContainer(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v SONtransferResponseContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APSONtransferResponseContainer(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONtransferResponseContainer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// VoiceSupportMatchIndicatorCodec binds the complete APER value type.
func VoiceSupportMatchIndicatorCodec() s02.VoiceSupportMatchIndicatorValueCodec {
	return UERadioCapabilityMatchResponseIEs().VoiceSupportMatchIndicator().Codec()
}
func BridgeCellStateIndicationAPERValueFieldContext(v *CellStateIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellStateIndicationAPERValueFieldReceived(v *CellStateIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCellStateIndicationAPERValueFieldReplay(v *CellStateIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCellStateIndicationAPERValueFieldWithoutReplay(v *CellStateIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellStateIndicationFieldExtCount(v *CellStateIndication) *int64   { return &v.extCount }
func BridgeCellStateIndicationFieldExtData(v *CellStateIndication) *[][]byte { return &v.extData }
func BridgeCellStateIndicationFieldExtOrigin(v *CellStateIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCellStateIndicationFieldExtPresent(v *CellStateIndication) *[]bool { return &v.extPresent }
func BridgeCellStateIndicationFieldExtWire(v *CellStateIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCellStateIndicationFieldNotificationCellListIndef(v *CellStateIndication) *bool {
	return &v.notificationCellListIndef
}
func BridgeCellStateIndicationFieldPerExtPadding(v *CellStateIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCellStateIndicationFieldPerPadding(v *CellStateIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCellStateIndicationFieldReceived(v *CellStateIndication) *bool { return &v.received }
func BridgeCellStateIndicationFieldReceivedAbsolute(v *CellStateIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeCellStateIndicationFieldReceivedBytes(v *CellStateIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellStateIndicationFieldReceivedLocation(v *CellStateIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellStateIndicationFieldReplay(v *CellStateIndication) *aper.Snapshot { return &v.replay }
func BridgeCellStateIndicationFieldStream(v *CellStateIndication) *aper.WireSpan { return &v.stream }
func BridgeCellStateIndicationFieldWithoutReplay(v *CellStateIndication) *bool {
	return &v.withoutReplay
}
func BridgeCellStateIndicationMethodMarshalAPERBudget(v *CellStateIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellStateIndicationMethodMarshalAPERBudgetValue(v *CellStateIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellStateIndicationMethodMarshalAPERChanged(v *CellStateIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellStateIndicationMethodMarshalAPERChangedValue(v *CellStateIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellStateIndicationMethodMarshalAPERLegacy(v *CellStateIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellStateIndicationMethodMarshalAPERNewValue(v *CellStateIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellStateIndicationMethodMarshalAPERPlanned(v *CellStateIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellStateIndicationMethodMarshalAPERTo(v *CellStateIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellStateIndicationMethodUnmarshalAPERFrom(v *CellStateIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellStateIndicationMethodUnmarshalAPERLegacy(v *CellStateIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellStateIndicationMethodUnmarshalAPERWithOptions(v *CellStateIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellStateIndicationValueCodecFieldCapture(v *CellStateIndicationValueCodec) *func(CellStateIndication, aper.DecodeState) (CellStateIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeCellStateIndicationValueCodecFieldCompare(v *CellStateIndicationValueCodec) *func(CellStateIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellStateIndicationValueCodecFieldContext(v *CellStateIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellStateIndicationValueCodecFieldDecode(v *CellStateIndicationValueCodec) *func([]byte, aper.DecodeState) (CellStateIndication, error) {
	return &v.decode
}
func BridgeCellStateIndicationValueCodecFieldEncode(v *CellStateIndicationValueCodec) *func(CellStateIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellStateIndicationValueCodecFieldPath(v *CellStateIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellStateIndicationValueCodecMethodEncodeBudgetValue(v CellStateIndicationValueCodec, a0 CellStateIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellStateIndicationValueCodecMethodEncodeChanged(v CellStateIndicationValueCodec, a0 CellStateIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateAcknowledgeAPERValueFieldContext(v *ENBConfigurationUpdateAcknowledgeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeAPERValueFieldReceived(v *ENBConfigurationUpdateAcknowledgeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeAPERValueFieldReplay(v *ENBConfigurationUpdateAcknowledgeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateAcknowledgeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateAcknowledgeFieldExtCount(v *ENBConfigurationUpdateAcknowledge) *int64 {
	return &v.extCount
}
func BridgeENBConfigurationUpdateAcknowledgeFieldExtData(v *ENBConfigurationUpdateAcknowledge) *[][]byte {
	return &v.extData
}
func BridgeENBConfigurationUpdateAcknowledgeFieldExtOrigin(v *ENBConfigurationUpdateAcknowledge) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBConfigurationUpdateAcknowledgeFieldExtPresent(v *ENBConfigurationUpdateAcknowledge) *[]bool {
	return &v.extPresent
}
func BridgeENBConfigurationUpdateAcknowledgeFieldExtWire(v *ENBConfigurationUpdateAcknowledge) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBConfigurationUpdateAcknowledgeFieldPerExtPadding(v *ENBConfigurationUpdateAcknowledge) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBConfigurationUpdateAcknowledgeFieldPerPadding(v *ENBConfigurationUpdateAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBConfigurationUpdateAcknowledgeFieldProtocolIEsIndef(v *ENBConfigurationUpdateAcknowledge) *bool {
	return &v.protocolIEsIndef
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReceived(v *ENBConfigurationUpdateAcknowledge) *bool {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReceivedAbsolute(v *ENBConfigurationUpdateAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReceivedBytes(v *ENBConfigurationUpdateAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReceivedLocation(v *ENBConfigurationUpdateAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReplay(v *ENBConfigurationUpdateAcknowledge) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeFieldStream(v *ENBConfigurationUpdateAcknowledge) *aper.WireSpan {
	return &v.stream
}
func BridgeENBConfigurationUpdateAcknowledgeFieldWithoutReplay(v *ENBConfigurationUpdateAcknowledge) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v *ENBConfigurationUpdateAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudgetValue(v *ENBConfigurationUpdateAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERChanged(v *ENBConfigurationUpdateAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERChangedValue(v *ENBConfigurationUpdateAcknowledge, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERLegacy(v *ENBConfigurationUpdateAcknowledge) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERNewValue(v *ENBConfigurationUpdateAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERPlanned(v *ENBConfigurationUpdateAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERTo(v *ENBConfigurationUpdateAcknowledge, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodUnmarshalAPERFrom(v *ENBConfigurationUpdateAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodUnmarshalAPERLegacy(v *ENBConfigurationUpdateAcknowledge, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodUnmarshalAPERWithOptions(v *ENBConfigurationUpdateAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldCapture(v *ENBConfigurationUpdateAcknowledgeValueCodec) *func(ENBConfigurationUpdateAcknowledge, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldCompare(v *ENBConfigurationUpdateAcknowledgeValueCodec) *func(ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldContext(v *ENBConfigurationUpdateAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldDecode(v *ENBConfigurationUpdateAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldEncode(v *ENBConfigurationUpdateAcknowledgeValueCodec) *func(ENBConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldPath(v *ENBConfigurationUpdateAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateAcknowledgeValueCodec, a0 ENBConfigurationUpdateAcknowledge, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecMethodEncodeChanged(v ENBConfigurationUpdateAcknowledgeValueCodec, a0 ENBConfigurationUpdateAcknowledge, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateFailureAPERValueFieldContext(v *ENBConfigurationUpdateFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureAPERValueFieldReceived(v *ENBConfigurationUpdateFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureAPERValueFieldReplay(v *ENBConfigurationUpdateFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateFailureFieldExtCount(v *ENBConfigurationUpdateFailure) *int64 {
	return &v.extCount
}
func BridgeENBConfigurationUpdateFailureFieldExtData(v *ENBConfigurationUpdateFailure) *[][]byte {
	return &v.extData
}
func BridgeENBConfigurationUpdateFailureFieldExtOrigin(v *ENBConfigurationUpdateFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBConfigurationUpdateFailureFieldExtPresent(v *ENBConfigurationUpdateFailure) *[]bool {
	return &v.extPresent
}
func BridgeENBConfigurationUpdateFailureFieldExtWire(v *ENBConfigurationUpdateFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBConfigurationUpdateFailureFieldPerExtPadding(v *ENBConfigurationUpdateFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBConfigurationUpdateFailureFieldPerPadding(v *ENBConfigurationUpdateFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBConfigurationUpdateFailureFieldProtocolIEsIndef(v *ENBConfigurationUpdateFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeENBConfigurationUpdateFailureFieldReceived(v *ENBConfigurationUpdateFailure) *bool {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureFieldReceivedAbsolute(v *ENBConfigurationUpdateFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeENBConfigurationUpdateFailureFieldReceivedBytes(v *ENBConfigurationUpdateFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBConfigurationUpdateFailureFieldReceivedLocation(v *ENBConfigurationUpdateFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBConfigurationUpdateFailureFieldReplay(v *ENBConfigurationUpdateFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureFieldStream(v *ENBConfigurationUpdateFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeENBConfigurationUpdateFailureFieldWithoutReplay(v *ENBConfigurationUpdateFailure) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(v *ENBConfigurationUpdateFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudgetValue(v *ENBConfigurationUpdateFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERChanged(v *ENBConfigurationUpdateFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERChangedValue(v *ENBConfigurationUpdateFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERLegacy(v *ENBConfigurationUpdateFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERNewValue(v *ENBConfigurationUpdateFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERPlanned(v *ENBConfigurationUpdateFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERTo(v *ENBConfigurationUpdateFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBConfigurationUpdateFailureMethodUnmarshalAPERFrom(v *ENBConfigurationUpdateFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateFailureMethodUnmarshalAPERLegacy(v *ENBConfigurationUpdateFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBConfigurationUpdateFailureMethodUnmarshalAPERWithOptions(v *ENBConfigurationUpdateFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldCapture(v *ENBConfigurationUpdateFailureValueCodec) *func(ENBConfigurationUpdateFailure, aper.DecodeState) (ENBConfigurationUpdateFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldCompare(v *ENBConfigurationUpdateFailureValueCodec) *func(ENBConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldContext(v *ENBConfigurationUpdateFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldDecode(v *ENBConfigurationUpdateFailureValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailure, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldEncode(v *ENBConfigurationUpdateFailureValueCodec) *func(ENBConfigurationUpdateFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldPath(v *ENBConfigurationUpdateFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateFailureValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateFailureValueCodec, a0 ENBConfigurationUpdateFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureValueCodecMethodEncodeChanged(v ENBConfigurationUpdateFailureValueCodec, a0 ENBConfigurationUpdateFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBStatusTransferAPERValueFieldContext(v *ENBStatusTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferAPERValueFieldReceived(v *ENBStatusTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBStatusTransferAPERValueFieldReplay(v *ENBStatusTransferAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferAPERValueFieldWithoutReplay(v *ENBStatusTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferFieldExtCount(v *ENBStatusTransfer) *int64   { return &v.extCount }
func BridgeENBStatusTransferFieldExtData(v *ENBStatusTransfer) *[][]byte { return &v.extData }
func BridgeENBStatusTransferFieldExtOrigin(v *ENBStatusTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBStatusTransferFieldExtPresent(v *ENBStatusTransfer) *[]bool       { return &v.extPresent }
func BridgeENBStatusTransferFieldExtWire(v *ENBStatusTransfer) *[]aper.WireSpan { return &v.extWire }
func BridgeENBStatusTransferFieldPerExtPadding(v *ENBStatusTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBStatusTransferFieldPerPadding(v *ENBStatusTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBStatusTransferFieldProtocolIEsIndef(v *ENBStatusTransfer) *bool {
	return &v.protocolIEsIndef
}
func BridgeENBStatusTransferFieldReceived(v *ENBStatusTransfer) *bool { return &v.received }
func BridgeENBStatusTransferFieldReceivedAbsolute(v *ENBStatusTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeENBStatusTransferFieldReceivedBytes(v *ENBStatusTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBStatusTransferFieldReceivedLocation(v *ENBStatusTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBStatusTransferFieldReplay(v *ENBStatusTransfer) *aper.Snapshot { return &v.replay }
func BridgeENBStatusTransferFieldStream(v *ENBStatusTransfer) *aper.WireSpan { return &v.stream }
func BridgeENBStatusTransferFieldWithoutReplay(v *ENBStatusTransfer) *bool   { return &v.withoutReplay }
func BridgeENBStatusTransferMethodMarshalAPERBudget(v *ENBStatusTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBStatusTransferMethodMarshalAPERBudgetValue(v *ENBStatusTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBStatusTransferMethodMarshalAPERChanged(v *ENBStatusTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBStatusTransferMethodMarshalAPERChangedValue(v *ENBStatusTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBStatusTransferMethodMarshalAPERLegacy(v *ENBStatusTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBStatusTransferMethodMarshalAPERNewValue(v *ENBStatusTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBStatusTransferMethodMarshalAPERPlanned(v *ENBStatusTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBStatusTransferMethodMarshalAPERTo(v *ENBStatusTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBStatusTransferMethodUnmarshalAPERFrom(v *ENBStatusTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBStatusTransferMethodUnmarshalAPERLegacy(v *ENBStatusTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBStatusTransferMethodUnmarshalAPERWithOptions(v *ENBStatusTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBStatusTransferValueCodecFieldCapture(v *ENBStatusTransferValueCodec) *func(ENBStatusTransfer, aper.DecodeState) (ENBStatusTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferValueCodecFieldCompare(v *ENBStatusTransferValueCodec) *func(ENBStatusTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferValueCodecFieldContext(v *ENBStatusTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferValueCodecFieldDecode(v *ENBStatusTransferValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransfer, error) {
	return &v.decode
}
func BridgeENBStatusTransferValueCodecFieldEncode(v *ENBStatusTransferValueCodec) *func(ENBStatusTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferValueCodecFieldPath(v *ENBStatusTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferValueCodecMethodEncodeBudgetValue(v ENBStatusTransferValueCodec, a0 ENBStatusTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBStatusTransferValueCodecMethodEncodeChanged(v ENBStatusTransferValueCodec, a0 ENBStatusTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterSystemMeasurementParametersAPERValueFieldContext(v *InterSystemMeasurementParametersAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementParametersAPERValueFieldReceived(v *InterSystemMeasurementParametersAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterSystemMeasurementParametersAPERValueFieldReplay(v *InterSystemMeasurementParametersAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemMeasurementParametersAPERValueFieldWithoutReplay(v *InterSystemMeasurementParametersAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemMeasurementParametersFieldExtCount(v *InterSystemMeasurementParameters) *int64 {
	return &v.extCount
}
func BridgeInterSystemMeasurementParametersFieldExtData(v *InterSystemMeasurementParameters) *[][]byte {
	return &v.extData
}
func BridgeInterSystemMeasurementParametersFieldExtOrigin(v *InterSystemMeasurementParameters) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeInterSystemMeasurementParametersFieldExtPresent(v *InterSystemMeasurementParameters) *[]bool {
	return &v.extPresent
}
func BridgeInterSystemMeasurementParametersFieldExtWire(v *InterSystemMeasurementParameters) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeInterSystemMeasurementParametersFieldIEExtensionsIndef(v *InterSystemMeasurementParameters) *bool {
	return &v.iEExtensionsIndef
}
func BridgeInterSystemMeasurementParametersFieldInterSystemMeasurementListIndef(v *InterSystemMeasurementParameters) *bool {
	return &v.interSystemMeasurementListIndef
}
func BridgeInterSystemMeasurementParametersFieldPerExtPadding(v *InterSystemMeasurementParameters) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeInterSystemMeasurementParametersFieldPerPadding(v *InterSystemMeasurementParameters) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeInterSystemMeasurementParametersFieldReceived(v *InterSystemMeasurementParameters) *bool {
	return &v.received
}
func BridgeInterSystemMeasurementParametersFieldReceivedAbsolute(v *InterSystemMeasurementParameters) *bool {
	return &v.receivedAbsolute
}
func BridgeInterSystemMeasurementParametersFieldReceivedBytes(v *InterSystemMeasurementParameters) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInterSystemMeasurementParametersFieldReceivedLocation(v *InterSystemMeasurementParameters) *aper.Location {
	return &v.receivedLocation
}
func BridgeInterSystemMeasurementParametersFieldReplay(v *InterSystemMeasurementParameters) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemMeasurementParametersFieldStream(v *InterSystemMeasurementParameters) *aper.WireSpan {
	return &v.stream
}
func BridgeInterSystemMeasurementParametersFieldWithoutReplay(v *InterSystemMeasurementParameters) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemMeasurementParametersMethodMarshalAPERBudget(v *InterSystemMeasurementParameters, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterSystemMeasurementParametersMethodMarshalAPERBudgetValue(v *InterSystemMeasurementParameters, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeInterSystemMeasurementParametersMethodMarshalAPERChanged(v *InterSystemMeasurementParameters, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterSystemMeasurementParametersMethodMarshalAPERChangedValue(v *InterSystemMeasurementParameters, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterSystemMeasurementParametersMethodMarshalAPERLegacy(v *InterSystemMeasurementParameters) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterSystemMeasurementParametersMethodMarshalAPERNewValue(v *InterSystemMeasurementParameters, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeInterSystemMeasurementParametersMethodMarshalAPERPlanned(v *InterSystemMeasurementParameters, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeInterSystemMeasurementParametersMethodMarshalAPERTo(v *InterSystemMeasurementParameters, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterSystemMeasurementParametersMethodUnmarshalAPERFrom(v *InterSystemMeasurementParameters, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterSystemMeasurementParametersMethodUnmarshalAPERLegacy(v *InterSystemMeasurementParameters, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterSystemMeasurementParametersMethodUnmarshalAPERWithOptions(v *InterSystemMeasurementParameters, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterSystemMeasurementParametersValueCodecFieldCapture(v *InterSystemMeasurementParametersValueCodec) *func(InterSystemMeasurementParameters, aper.DecodeState) (InterSystemMeasurementParameters, aper.Snapshot) {
	return &v.capture
}
func BridgeInterSystemMeasurementParametersValueCodecFieldCompare(v *InterSystemMeasurementParametersValueCodec) *func(InterSystemMeasurementParameters, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterSystemMeasurementParametersValueCodecFieldContext(v *InterSystemMeasurementParametersValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementParametersValueCodecFieldDecode(v *InterSystemMeasurementParametersValueCodec) *func([]byte, aper.DecodeState) (InterSystemMeasurementParameters, error) {
	return &v.decode
}
func BridgeInterSystemMeasurementParametersValueCodecFieldEncode(v *InterSystemMeasurementParametersValueCodec) *func(InterSystemMeasurementParameters, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterSystemMeasurementParametersValueCodecFieldPath(v *InterSystemMeasurementParametersValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterSystemMeasurementParametersValueCodecMethodEncodeBudgetValue(v InterSystemMeasurementParametersValueCodec, a0 InterSystemMeasurementParameters, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInterSystemMeasurementParametersValueCodecMethodEncodeChanged(v InterSystemMeasurementParametersValueCodec, a0 InterSystemMeasurementParameters, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeIntersystemMeasurementConfigurationAPERValueFieldContext(v *IntersystemMeasurementConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntersystemMeasurementConfigurationAPERValueFieldReceived(v *IntersystemMeasurementConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeIntersystemMeasurementConfigurationAPERValueFieldReplay(v *IntersystemMeasurementConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeIntersystemMeasurementConfigurationAPERValueFieldWithoutReplay(v *IntersystemMeasurementConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeIntersystemMeasurementConfigurationFieldExtCount(v *IntersystemMeasurementConfiguration) *int64 {
	return &v.extCount
}
func BridgeIntersystemMeasurementConfigurationFieldExtData(v *IntersystemMeasurementConfiguration) *[][]byte {
	return &v.extData
}
func BridgeIntersystemMeasurementConfigurationFieldExtOrigin(v *IntersystemMeasurementConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeIntersystemMeasurementConfigurationFieldExtPresent(v *IntersystemMeasurementConfiguration) *[]bool {
	return &v.extPresent
}
func BridgeIntersystemMeasurementConfigurationFieldExtWire(v *IntersystemMeasurementConfiguration) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeIntersystemMeasurementConfigurationFieldIEExtensionsIndef(v *IntersystemMeasurementConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeIntersystemMeasurementConfigurationFieldPerExtPadding(v *IntersystemMeasurementConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeIntersystemMeasurementConfigurationFieldPerPadding(v *IntersystemMeasurementConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeIntersystemMeasurementConfigurationFieldReceived(v *IntersystemMeasurementConfiguration) *bool {
	return &v.received
}
func BridgeIntersystemMeasurementConfigurationFieldReceivedAbsolute(v *IntersystemMeasurementConfiguration) *bool {
	return &v.receivedAbsolute
}
func BridgeIntersystemMeasurementConfigurationFieldReceivedBytes(v *IntersystemMeasurementConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeIntersystemMeasurementConfigurationFieldReceivedLocation(v *IntersystemMeasurementConfiguration) *aper.Location {
	return &v.receivedLocation
}
func BridgeIntersystemMeasurementConfigurationFieldReplay(v *IntersystemMeasurementConfiguration) *aper.Snapshot {
	return &v.replay
}
func BridgeIntersystemMeasurementConfigurationFieldStream(v *IntersystemMeasurementConfiguration) *aper.WireSpan {
	return &v.stream
}
func BridgeIntersystemMeasurementConfigurationFieldWithoutReplay(v *IntersystemMeasurementConfiguration) *bool {
	return &v.withoutReplay
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERBudget(v *IntersystemMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERBudgetValue(v *IntersystemMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERChanged(v *IntersystemMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERChangedValue(v *IntersystemMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERLegacy(v *IntersystemMeasurementConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERNewValue(v *IntersystemMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERPlanned(v *IntersystemMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERTo(v *IntersystemMeasurementConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeIntersystemMeasurementConfigurationMethodUnmarshalAPERFrom(v *IntersystemMeasurementConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeIntersystemMeasurementConfigurationMethodUnmarshalAPERLegacy(v *IntersystemMeasurementConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeIntersystemMeasurementConfigurationMethodUnmarshalAPERWithOptions(v *IntersystemMeasurementConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldCapture(v *IntersystemMeasurementConfigurationValueCodec) *func(IntersystemMeasurementConfiguration, aper.DecodeState) (IntersystemMeasurementConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldCompare(v *IntersystemMeasurementConfigurationValueCodec) *func(IntersystemMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldContext(v *IntersystemMeasurementConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldDecode(v *IntersystemMeasurementConfigurationValueCodec) *func([]byte, aper.DecodeState) (IntersystemMeasurementConfiguration, error) {
	return &v.decode
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldEncode(v *IntersystemMeasurementConfigurationValueCodec) *func(IntersystemMeasurementConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldPath(v *IntersystemMeasurementConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntersystemMeasurementConfigurationValueCodecMethodEncodeBudgetValue(v IntersystemMeasurementConfigurationValueCodec, a0 IntersystemMeasurementConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeIntersystemMeasurementConfigurationValueCodecMethodEncodeChanged(v IntersystemMeasurementConfigurationValueCodec, a0 IntersystemMeasurementConfiguration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLoggedMBSFNMDTAPERValueFieldContext(v *LoggedMBSFNMDTAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMBSFNMDTAPERValueFieldReceived(v *LoggedMBSFNMDTAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLoggedMBSFNMDTAPERValueFieldReplay(v *LoggedMBSFNMDTAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLoggedMBSFNMDTAPERValueFieldWithoutReplay(v *LoggedMBSFNMDTAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLoggedMBSFNMDTFieldExtCount(v *LoggedMBSFNMDT) *int64                { return &v.extCount }
func BridgeLoggedMBSFNMDTFieldExtData(v *LoggedMBSFNMDT) *[][]byte              { return &v.extData }
func BridgeLoggedMBSFNMDTFieldExtOrigin(v *LoggedMBSFNMDT) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeLoggedMBSFNMDTFieldExtPresent(v *LoggedMBSFNMDT) *[]bool             { return &v.extPresent }
func BridgeLoggedMBSFNMDTFieldExtWire(v *LoggedMBSFNMDT) *[]aper.WireSpan       { return &v.extWire }
func BridgeLoggedMBSFNMDTFieldIEExtensionsIndef(v *LoggedMBSFNMDT) *bool        { return &v.iEExtensionsIndef }
func BridgeLoggedMBSFNMDTFieldMBSFNResultToLogIndef(v *LoggedMBSFNMDT) *bool {
	return &v.mBSFNResultToLogIndef
}
func BridgeLoggedMBSFNMDTFieldPerExtPadding(v *LoggedMBSFNMDT) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeLoggedMBSFNMDTFieldPerPadding(v *LoggedMBSFNMDT) *aper.FinalPadding { return &v.perPadding }
func BridgeLoggedMBSFNMDTFieldReceived(v *LoggedMBSFNMDT) *bool                { return &v.received }
func BridgeLoggedMBSFNMDTFieldReceivedAbsolute(v *LoggedMBSFNMDT) *bool        { return &v.receivedAbsolute }
func BridgeLoggedMBSFNMDTFieldReceivedBytes(v *LoggedMBSFNMDT) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLoggedMBSFNMDTFieldReceivedLocation(v *LoggedMBSFNMDT) *aper.Location {
	return &v.receivedLocation
}
func BridgeLoggedMBSFNMDTFieldReplay(v *LoggedMBSFNMDT) *aper.Snapshot { return &v.replay }
func BridgeLoggedMBSFNMDTFieldStream(v *LoggedMBSFNMDT) *aper.WireSpan { return &v.stream }
func BridgeLoggedMBSFNMDTFieldWithoutReplay(v *LoggedMBSFNMDT) *bool   { return &v.withoutReplay }
func BridgeLoggedMBSFNMDTMethodMarshalAPERBudget(v *LoggedMBSFNMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLoggedMBSFNMDTMethodMarshalAPERBudgetValue(v *LoggedMBSFNMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLoggedMBSFNMDTMethodMarshalAPERChanged(v *LoggedMBSFNMDT, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLoggedMBSFNMDTMethodMarshalAPERChangedValue(v *LoggedMBSFNMDT, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLoggedMBSFNMDTMethodMarshalAPERLegacy(v *LoggedMBSFNMDT) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLoggedMBSFNMDTMethodMarshalAPERNewValue(v *LoggedMBSFNMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLoggedMBSFNMDTMethodMarshalAPERPlanned(v *LoggedMBSFNMDT, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLoggedMBSFNMDTMethodMarshalAPERTo(v *LoggedMBSFNMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLoggedMBSFNMDTMethodUnmarshalAPERFrom(v *LoggedMBSFNMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLoggedMBSFNMDTMethodUnmarshalAPERLegacy(v *LoggedMBSFNMDT, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLoggedMBSFNMDTMethodUnmarshalAPERWithOptions(v *LoggedMBSFNMDT, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLoggedMBSFNMDTValueCodecFieldCapture(v *LoggedMBSFNMDTValueCodec) *func(LoggedMBSFNMDT, aper.DecodeState) (LoggedMBSFNMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggedMBSFNMDTValueCodecFieldCompare(v *LoggedMBSFNMDTValueCodec) *func(LoggedMBSFNMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggedMBSFNMDTValueCodecFieldContext(v *LoggedMBSFNMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMBSFNMDTValueCodecFieldDecode(v *LoggedMBSFNMDTValueCodec) *func([]byte, aper.DecodeState) (LoggedMBSFNMDT, error) {
	return &v.decode
}
func BridgeLoggedMBSFNMDTValueCodecFieldEncode(v *LoggedMBSFNMDTValueCodec) *func(LoggedMBSFNMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggedMBSFNMDTValueCodecFieldPath(v *LoggedMBSFNMDTValueCodec) *aper.Path { return &v.path }
func BridgeLoggedMBSFNMDTValueCodecMethodEncodeBudgetValue(v LoggedMBSFNMDTValueCodec, a0 LoggedMBSFNMDT, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLoggedMBSFNMDTValueCodecMethodEncodeChanged(v LoggedMBSFNMDTValueCodec, a0 LoggedMBSFNMDT, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTModeExtensionIEIEContainerAPERValueFieldContext(v *MDTModeExtensionIEIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEContainerAPERValueFieldReceived(v *MDTModeExtensionIEIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTModeExtensionIEIEContainerAPERValueFieldReplay(v *MDTModeExtensionIEIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionIEIEContainerAPERValueFieldWithoutReplay(v *MDTModeExtensionIEIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldCapture(v *MDTModeExtensionIEIEContainerValueCodec) *func(MDTModeExtensionIEIEContainer, aper.DecodeState) (MDTModeExtensionIEIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldCompare(v *MDTModeExtensionIEIEContainerValueCodec) *func(MDTModeExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldContext(v *MDTModeExtensionIEIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(v *MDTModeExtensionIEIEContainerValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEContainer, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(v *MDTModeExtensionIEIEContainerValueCodec) *func(MDTModeExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldPath(v *MDTModeExtensionIEIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEContainerValueCodecMethodEncodeBudgetValue(v MDTModeExtensionIEIEContainerValueCodec, a0 MDTModeExtensionIEIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTModeExtensionIEIEContainerValueCodecMethodEncodeChanged(v MDTModeExtensionIEIEContainerValueCodec, a0 MDTModeExtensionIEIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTModeExtensionIEIEFieldAPERValueFieldContext(v *MDTModeExtensionIEIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEFieldAPERValueFieldReceived(v *MDTModeExtensionIEIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTModeExtensionIEIEFieldAPERValueFieldReplay(v *MDTModeExtensionIEIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionIEIEFieldAPERValueFieldWithoutReplay(v *MDTModeExtensionIEIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTModeExtensionIEIEFieldFieldReceived(v *MDTModeExtensionIEIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMDTModeExtensionIEIEFieldFieldReplay(v *MDTModeExtensionIEIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionIEIEFieldFieldStream(v *MDTModeExtensionIEIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMDTModeExtensionIEIEFieldFieldWithoutReplay(v *MDTModeExtensionIEIEField) *bool {
	return &v.withoutReplay
}
func BridgeMDTModeExtensionIEIEFieldMethodMarshalAPERTo(v *MDTModeExtensionIEIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(v *MDTModeExtensionIEIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldCapture(v *MDTModeExtensionIEIEFieldValueCodec) *func(MDTModeExtensionIEIEField, aper.DecodeState) (MDTModeExtensionIEIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldCompare(v *MDTModeExtensionIEIEFieldValueCodec) *func(MDTModeExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldContext(v *MDTModeExtensionIEIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldDecode(v *MDTModeExtensionIEIEFieldValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEField, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldEncode(v *MDTModeExtensionIEIEFieldValueCodec) *func(MDTModeExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldPath(v *MDTModeExtensionIEIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEFieldValueCodecMethodEncodeBudgetValue(v MDTModeExtensionIEIEFieldValueCodec, a0 MDTModeExtensionIEIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTModeExtensionIEIEFieldValueCodecMethodEncodeChanged(v MDTModeExtensionIEIEFieldValueCodec, a0 MDTModeExtensionIEIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListAPERValueFieldContext(v *MDTModeExtensionIEIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListAPERValueFieldReceived(v *MDTModeExtensionIEIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListAPERValueFieldReplay(v *MDTModeExtensionIEIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *MDTModeExtensionIEIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueERABIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldContext(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldPath(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v MDTModeExtensionIEIEValueERABIEContainerListValueCodec, a0 MDTModeExtensionIEIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecMethodEncodeChanged(v MDTModeExtensionIEIEValueERABIEContainerListValueCodec, a0 MDTModeExtensionIEIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTModeExtensionIEIEValueFieldId(v *MDTModeExtensionIEIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMDTModeExtensionIEIEValueFieldIsOpaque(v *MDTModeExtensionIEIEValue) *bool {
	return &v.isOpaque
}
func BridgeMDTModeExtensionIEIEValueFieldOpaque(v *MDTModeExtensionIEIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMDTModeExtensionIEIEValueFieldReceived(v *MDTModeExtensionIEIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTModeExtensionIEIEValueFieldReplay(v *MDTModeExtensionIEIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionIEIEValueFieldRowLoggedMBSFNMDT(v *MDTModeExtensionIEIEValue) **LoggedMBSFNMDT {
	return &v.rowLoggedMBSFNMDT
}
func BridgeMDTModeExtensionIEIEValueMethodCaptureSemantics(v MDTModeExtensionIEIEValue, a0 aper.SemanticCapture) MDTModeExtensionIEIEValue {
	return v.captureSemantics(a0)
}
func BridgeMDTModeExtensionIEIEValueMethodCompareSemantics(v MDTModeExtensionIEIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMDTModeExtensionIEIEValueMethodDecode(v MDTModeExtensionIEIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MDTModeExtensionIEIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMDTModeExtensionIEIEValueMethodEncode(v MDTModeExtensionIEIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMDTModeExtensionIEIEValueMethodEncodeFresh(v MDTModeExtensionIEIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMDTModeExtensionIEIEValueMethodMatchesID(v MDTModeExtensionIEIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMDTModeExtensionIEIEValueMethodReason(v MDTModeExtensionIEIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMDTModeExtensionIEIEValueMethodRule(v MDTModeExtensionIEIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec, a0 MDTModeExtensionIEIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec, a0 MDTModeExtensionIEIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListAPERValueFieldContext(v *MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListAPERValueFieldReceived(v *MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListAPERValueFieldReplay(v *MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldPath(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec, a0 MDTModeExtensionIEIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec, a0 MDTModeExtensionIEIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTModeExtensionIELoggedMBSFNMDTIEBindingFieldCodec(v *MDTModeExtensionIELoggedMBSFNMDTIEBinding) *LoggedMBSFNMDTValueCodec {
	return &v.codec
}
func BridgeMDTModeExtensionIELoggedMBSFNMDTIEBindingFieldGet(v *MDTModeExtensionIELoggedMBSFNMDTIEBinding) *func(*MDTModeExtensionIEIEValue) (*LoggedMBSFNMDT, bool) {
	return &v.get
}
func BridgeMDTModeExtensionIELoggedMBSFNMDTIEBindingFieldInfo(v *MDTModeExtensionIELoggedMBSFNMDTIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMDTModeExtensionIELoggedMBSFNMDTIEBindingFieldInject(v *MDTModeExtensionIELoggedMBSFNMDTIEBinding) *func(LoggedMBSFNMDT) MDTModeExtensionIEIEValue {
	return &v.inject
}
func BridgeMDTModeExtensionIETableMethodInfoLoggedMBSFNMDT(v MDTModeExtensionIETable) s00.FieldInfo {
	return v.infoLoggedMBSFNMDT()
}
func BridgeMultiCellLoadReportingRequestAPERValueFieldContext(v *MultiCellLoadReportingRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMultiCellLoadReportingRequestAPERValueFieldReceived(v *MultiCellLoadReportingRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMultiCellLoadReportingRequestAPERValueFieldReplay(v *MultiCellLoadReportingRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMultiCellLoadReportingRequestAPERValueFieldWithoutReplay(v *MultiCellLoadReportingRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMultiCellLoadReportingRequestFieldExtCount(v *MultiCellLoadReportingRequest) *int64 {
	return &v.extCount
}
func BridgeMultiCellLoadReportingRequestFieldExtData(v *MultiCellLoadReportingRequest) *[][]byte {
	return &v.extData
}
func BridgeMultiCellLoadReportingRequestFieldExtOrigin(v *MultiCellLoadReportingRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMultiCellLoadReportingRequestFieldExtPresent(v *MultiCellLoadReportingRequest) *[]bool {
	return &v.extPresent
}
func BridgeMultiCellLoadReportingRequestFieldExtWire(v *MultiCellLoadReportingRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMultiCellLoadReportingRequestFieldPerExtPadding(v *MultiCellLoadReportingRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMultiCellLoadReportingRequestFieldPerPadding(v *MultiCellLoadReportingRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMultiCellLoadReportingRequestFieldReceived(v *MultiCellLoadReportingRequest) *bool {
	return &v.received
}
func BridgeMultiCellLoadReportingRequestFieldReceivedAbsolute(v *MultiCellLoadReportingRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeMultiCellLoadReportingRequestFieldReceivedBytes(v *MultiCellLoadReportingRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMultiCellLoadReportingRequestFieldReceivedLocation(v *MultiCellLoadReportingRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeMultiCellLoadReportingRequestFieldReplay(v *MultiCellLoadReportingRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeMultiCellLoadReportingRequestFieldRequestedCellListIndef(v *MultiCellLoadReportingRequest) *bool {
	return &v.requestedCellListIndef
}
func BridgeMultiCellLoadReportingRequestFieldStream(v *MultiCellLoadReportingRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeMultiCellLoadReportingRequestFieldWithoutReplay(v *MultiCellLoadReportingRequest) *bool {
	return &v.withoutReplay
}
func BridgeMultiCellLoadReportingRequestMethodMarshalAPERBudget(v *MultiCellLoadReportingRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMultiCellLoadReportingRequestMethodMarshalAPERBudgetValue(v *MultiCellLoadReportingRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMultiCellLoadReportingRequestMethodMarshalAPERChanged(v *MultiCellLoadReportingRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMultiCellLoadReportingRequestMethodMarshalAPERChangedValue(v *MultiCellLoadReportingRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMultiCellLoadReportingRequestMethodMarshalAPERLegacy(v *MultiCellLoadReportingRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMultiCellLoadReportingRequestMethodMarshalAPERNewValue(v *MultiCellLoadReportingRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMultiCellLoadReportingRequestMethodMarshalAPERPlanned(v *MultiCellLoadReportingRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMultiCellLoadReportingRequestMethodMarshalAPERTo(v *MultiCellLoadReportingRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMultiCellLoadReportingRequestMethodUnmarshalAPERFrom(v *MultiCellLoadReportingRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMultiCellLoadReportingRequestMethodUnmarshalAPERLegacy(v *MultiCellLoadReportingRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMultiCellLoadReportingRequestMethodUnmarshalAPERWithOptions(v *MultiCellLoadReportingRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMultiCellLoadReportingRequestValueCodecFieldCapture(v *MultiCellLoadReportingRequestValueCodec) *func(MultiCellLoadReportingRequest, aper.DecodeState) (MultiCellLoadReportingRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeMultiCellLoadReportingRequestValueCodecFieldCompare(v *MultiCellLoadReportingRequestValueCodec) *func(MultiCellLoadReportingRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMultiCellLoadReportingRequestValueCodecFieldContext(v *MultiCellLoadReportingRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMultiCellLoadReportingRequestValueCodecFieldDecode(v *MultiCellLoadReportingRequestValueCodec) *func([]byte, aper.DecodeState) (MultiCellLoadReportingRequest, error) {
	return &v.decode
}
func BridgeMultiCellLoadReportingRequestValueCodecFieldEncode(v *MultiCellLoadReportingRequestValueCodec) *func(MultiCellLoadReportingRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMultiCellLoadReportingRequestValueCodecFieldPath(v *MultiCellLoadReportingRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeMultiCellLoadReportingRequestValueCodecMethodEncodeBudgetValue(v MultiCellLoadReportingRequestValueCodec, a0 MultiCellLoadReportingRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMultiCellLoadReportingRequestValueCodecMethodEncodeChanged(v MultiCellLoadReportingRequestValueCodec, a0 MultiCellLoadReportingRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePC5QoSParametersAPERValueFieldContext(v *PC5QoSParametersAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSParametersAPERValueFieldReceived(v *PC5QoSParametersAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePC5QoSParametersAPERValueFieldReplay(v *PC5QoSParametersAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePC5QoSParametersAPERValueFieldWithoutReplay(v *PC5QoSParametersAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePC5QoSParametersFieldExtCount(v *PC5QoSParameters) *int64   { return &v.extCount }
func BridgePC5QoSParametersFieldExtData(v *PC5QoSParameters) *[][]byte { return &v.extData }
func BridgePC5QoSParametersFieldExtOrigin(v *PC5QoSParameters) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePC5QoSParametersFieldExtPresent(v *PC5QoSParameters) *[]bool       { return &v.extPresent }
func BridgePC5QoSParametersFieldExtWire(v *PC5QoSParameters) *[]aper.WireSpan { return &v.extWire }
func BridgePC5QoSParametersFieldIEExtensionsIndef(v *PC5QoSParameters) *bool {
	return &v.iEExtensionsIndef
}
func BridgePC5QoSParametersFieldPc5QoSFlowListIndef(v *PC5QoSParameters) *bool {
	return &v.pc5QoSFlowListIndef
}
func BridgePC5QoSParametersFieldPerExtPadding(v *PC5QoSParameters) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePC5QoSParametersFieldPerPadding(v *PC5QoSParameters) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePC5QoSParametersFieldReceived(v *PC5QoSParameters) *bool { return &v.received }
func BridgePC5QoSParametersFieldReceivedAbsolute(v *PC5QoSParameters) *bool {
	return &v.receivedAbsolute
}
func BridgePC5QoSParametersFieldReceivedBytes(v *PC5QoSParameters) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePC5QoSParametersFieldReceivedLocation(v *PC5QoSParameters) *aper.Location {
	return &v.receivedLocation
}
func BridgePC5QoSParametersFieldReplay(v *PC5QoSParameters) *aper.Snapshot { return &v.replay }
func BridgePC5QoSParametersFieldStream(v *PC5QoSParameters) *aper.WireSpan { return &v.stream }
func BridgePC5QoSParametersFieldWithoutReplay(v *PC5QoSParameters) *bool   { return &v.withoutReplay }
func BridgePC5QoSParametersMethodMarshalAPERBudget(v *PC5QoSParameters, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePC5QoSParametersMethodMarshalAPERBudgetValue(v *PC5QoSParameters, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePC5QoSParametersMethodMarshalAPERChanged(v *PC5QoSParameters, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePC5QoSParametersMethodMarshalAPERChangedValue(v *PC5QoSParameters, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePC5QoSParametersMethodMarshalAPERLegacy(v *PC5QoSParameters) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePC5QoSParametersMethodMarshalAPERNewValue(v *PC5QoSParameters, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePC5QoSParametersMethodMarshalAPERPlanned(v *PC5QoSParameters, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePC5QoSParametersMethodMarshalAPERTo(v *PC5QoSParameters, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePC5QoSParametersMethodUnmarshalAPERFrom(v *PC5QoSParameters, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePC5QoSParametersMethodUnmarshalAPERLegacy(v *PC5QoSParameters, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePC5QoSParametersMethodUnmarshalAPERWithOptions(v *PC5QoSParameters, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePC5QoSParametersValueCodecFieldCapture(v *PC5QoSParametersValueCodec) *func(PC5QoSParameters, aper.DecodeState) (PC5QoSParameters, aper.Snapshot) {
	return &v.capture
}
func BridgePC5QoSParametersValueCodecFieldCompare(v *PC5QoSParametersValueCodec) *func(PC5QoSParameters, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5QoSParametersValueCodecFieldContext(v *PC5QoSParametersValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSParametersValueCodecFieldDecode(v *PC5QoSParametersValueCodec) *func([]byte, aper.DecodeState) (PC5QoSParameters, error) {
	return &v.decode
}
func BridgePC5QoSParametersValueCodecFieldEncode(v *PC5QoSParametersValueCodec) *func(PC5QoSParameters, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5QoSParametersValueCodecFieldPath(v *PC5QoSParametersValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5QoSParametersValueCodecMethodEncodeBudgetValue(v PC5QoSParametersValueCodec, a0 PC5QoSParameters, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePC5QoSParametersValueCodecMethodEncodeChanged(v PC5QoSParametersValueCodec, a0 PC5QoSParameters, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONtransferRequestContainerAPERValueFieldContext(v *SONtransferRequestContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONtransferRequestContainerAPERValueFieldReceived(v *SONtransferRequestContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONtransferRequestContainerAPERValueFieldReplay(v *SONtransferRequestContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONtransferRequestContainerAPERValueFieldWithoutReplay(v *SONtransferRequestContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONtransferRequestContainerFieldPerOpenTypePadding(v *SONtransferRequestContainer) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSONtransferRequestContainerFieldPerPadding(v *SONtransferRequestContainer) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSONtransferRequestContainerFieldReceived(v *SONtransferRequestContainer) *bool {
	return &v.received
}
func BridgeSONtransferRequestContainerFieldReceivedAbsolute(v *SONtransferRequestContainer) *bool {
	return &v.receivedAbsolute
}
func BridgeSONtransferRequestContainerFieldReceivedBytes(v *SONtransferRequestContainer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSONtransferRequestContainerFieldReceivedLocation(v *SONtransferRequestContainer) *aper.Location {
	return &v.receivedLocation
}
func BridgeSONtransferRequestContainerFieldReplay(v *SONtransferRequestContainer) *aper.Snapshot {
	return &v.replay
}
func BridgeSONtransferRequestContainerFieldStream(v *SONtransferRequestContainer) *aper.WireSpan {
	return &v.stream
}
func BridgeSONtransferRequestContainerFieldWithoutReplay(v *SONtransferRequestContainer) *bool {
	return &v.withoutReplay
}
func BridgeSONtransferRequestContainerMethodMarshalAPERBudget(v *SONtransferRequestContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONtransferRequestContainerMethodMarshalAPERBudgetValue(v *SONtransferRequestContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSONtransferRequestContainerMethodMarshalAPERChanged(v *SONtransferRequestContainer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSONtransferRequestContainerMethodMarshalAPERChangedValue(v *SONtransferRequestContainer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSONtransferRequestContainerMethodMarshalAPERLegacy(v *SONtransferRequestContainer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSONtransferRequestContainerMethodMarshalAPERNewValue(v *SONtransferRequestContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSONtransferRequestContainerMethodMarshalAPERPlanned(v *SONtransferRequestContainer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSONtransferRequestContainerMethodMarshalAPERTo(v *SONtransferRequestContainer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONtransferRequestContainerMethodUnmarshalAPERFrom(v *SONtransferRequestContainer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONtransferRequestContainerMethodUnmarshalAPERLegacy(v *SONtransferRequestContainer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSONtransferRequestContainerMethodUnmarshalAPERWithOptions(v *SONtransferRequestContainer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSONtransferRequestContainerValueCodecFieldCapture(v *SONtransferRequestContainerValueCodec) *func(SONtransferRequestContainer, aper.DecodeState) (SONtransferRequestContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSONtransferRequestContainerValueCodecFieldCompare(v *SONtransferRequestContainerValueCodec) *func(SONtransferRequestContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONtransferRequestContainerValueCodecFieldContext(v *SONtransferRequestContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONtransferRequestContainerValueCodecFieldDecode(v *SONtransferRequestContainerValueCodec) *func([]byte, aper.DecodeState) (SONtransferRequestContainer, error) {
	return &v.decode
}
func BridgeSONtransferRequestContainerValueCodecFieldEncode(v *SONtransferRequestContainerValueCodec) *func(SONtransferRequestContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONtransferRequestContainerValueCodecFieldPath(v *SONtransferRequestContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONtransferRequestContainerValueCodecMethodEncodeBudgetValue(v SONtransferRequestContainerValueCodec, a0 SONtransferRequestContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONtransferRequestContainerValueCodecMethodEncodeChanged(v SONtransferRequestContainerValueCodec, a0 SONtransferRequestContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONtransferResponseContainerAPERValueFieldContext(v *SONtransferResponseContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONtransferResponseContainerAPERValueFieldReceived(v *SONtransferResponseContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONtransferResponseContainerAPERValueFieldReplay(v *SONtransferResponseContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONtransferResponseContainerAPERValueFieldWithoutReplay(v *SONtransferResponseContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONtransferResponseContainerFieldPerOpenTypePadding(v *SONtransferResponseContainer) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSONtransferResponseContainerFieldPerPadding(v *SONtransferResponseContainer) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSONtransferResponseContainerFieldReceived(v *SONtransferResponseContainer) *bool {
	return &v.received
}
func BridgeSONtransferResponseContainerFieldReceivedAbsolute(v *SONtransferResponseContainer) *bool {
	return &v.receivedAbsolute
}
func BridgeSONtransferResponseContainerFieldReceivedBytes(v *SONtransferResponseContainer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSONtransferResponseContainerFieldReceivedLocation(v *SONtransferResponseContainer) *aper.Location {
	return &v.receivedLocation
}
func BridgeSONtransferResponseContainerFieldReplay(v *SONtransferResponseContainer) *aper.Snapshot {
	return &v.replay
}
func BridgeSONtransferResponseContainerFieldStream(v *SONtransferResponseContainer) *aper.WireSpan {
	return &v.stream
}
func BridgeSONtransferResponseContainerFieldWithoutReplay(v *SONtransferResponseContainer) *bool {
	return &v.withoutReplay
}
func BridgeSONtransferResponseContainerMethodMarshalAPERBudget(v *SONtransferResponseContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONtransferResponseContainerMethodMarshalAPERBudgetValue(v *SONtransferResponseContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSONtransferResponseContainerMethodMarshalAPERChanged(v *SONtransferResponseContainer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSONtransferResponseContainerMethodMarshalAPERChangedValue(v *SONtransferResponseContainer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSONtransferResponseContainerMethodMarshalAPERLegacy(v *SONtransferResponseContainer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSONtransferResponseContainerMethodMarshalAPERNewValue(v *SONtransferResponseContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSONtransferResponseContainerMethodMarshalAPERPlanned(v *SONtransferResponseContainer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSONtransferResponseContainerMethodMarshalAPERTo(v *SONtransferResponseContainer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONtransferResponseContainerMethodUnmarshalAPERFrom(v *SONtransferResponseContainer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONtransferResponseContainerMethodUnmarshalAPERLegacy(v *SONtransferResponseContainer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSONtransferResponseContainerMethodUnmarshalAPERWithOptions(v *SONtransferResponseContainer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSONtransferResponseContainerValueCodecFieldCapture(v *SONtransferResponseContainerValueCodec) *func(SONtransferResponseContainer, aper.DecodeState) (SONtransferResponseContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSONtransferResponseContainerValueCodecFieldCompare(v *SONtransferResponseContainerValueCodec) *func(SONtransferResponseContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONtransferResponseContainerValueCodecFieldContext(v *SONtransferResponseContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONtransferResponseContainerValueCodecFieldDecode(v *SONtransferResponseContainerValueCodec) *func([]byte, aper.DecodeState) (SONtransferResponseContainer, error) {
	return &v.decode
}
func BridgeSONtransferResponseContainerValueCodecFieldEncode(v *SONtransferResponseContainerValueCodec) *func(SONtransferResponseContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONtransferResponseContainerValueCodecFieldPath(v *SONtransferResponseContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONtransferResponseContainerValueCodecMethodEncodeBudgetValue(v SONtransferResponseContainerValueCodec, a0 SONtransferResponseContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONtransferResponseContainerValueCodecMethodEncodeChanged(v SONtransferResponseContainerValueCodec, a0 SONtransferResponseContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDMappingResponseIETableMethodInfoCriticalityDiagnostics(v UERadioCapabilityIDMappingResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUERadioCapabilityIDMappingResponseIETableMethodInfoUERadioCapability(v UERadioCapabilityIDMappingResponseIETable) s00.FieldInfo {
	return v.infoUERadioCapability()
}
func BridgeUERadioCapabilityIDMappingResponseIETableMethodInfoUERadioCapabilityID(v UERadioCapabilityIDMappingResponseIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *func(s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *func(s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *func(s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec, a0 s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec, a0 s23.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBindingFieldCodec(v *UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) *s02.UERadioCapabilityIDValueCodec {
	return &v.codec
}
func BridgeUERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBindingFieldGet(v *UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) *func(*s23.UERadioCapabilityIDMappingResponseIEValue) (*s00.UERadioCapabilityID, bool) {
	return &v.get
}
func BridgeUERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBindingFieldInfo(v *UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBindingFieldInject(v *UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) *func(s00.UERadioCapabilityID) s23.UERadioCapabilityIDMappingResponseIEValue {
	return &v.inject
}
func BridgeUERadioCapabilityIDMappingResponseUERadioCapabilityIEBindingFieldCodec(v *UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) *s02.UERadioCapabilityValueCodec {
	return &v.codec
}
func BridgeUERadioCapabilityIDMappingResponseUERadioCapabilityIEBindingFieldGet(v *UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) *func(*s23.UERadioCapabilityIDMappingResponseIEValue) (*s00.UERadioCapability, bool) {
	return &v.get
}
func BridgeUERadioCapabilityIDMappingResponseUERadioCapabilityIEBindingFieldInfo(v *UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUERadioCapabilityIDMappingResponseUERadioCapabilityIEBindingFieldInject(v *UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) *func(s00.UERadioCapability) s23.UERadioCapabilityIDMappingResponseIEValue {
	return &v.inject
}
func BridgeUERadioCapabilityMatchResponseCriticalityDiagnosticsIEBindingFieldCodec(v *UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUERadioCapabilityMatchResponseCriticalityDiagnosticsIEBindingFieldGet(v *UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) *func(*UERadioCapabilityMatchResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUERadioCapabilityMatchResponseCriticalityDiagnosticsIEBindingFieldInfo(v *UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUERadioCapabilityMatchResponseCriticalityDiagnosticsIEBindingFieldInject(v *UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) UERadioCapabilityMatchResponseIEValue {
	return &v.inject
}
func BridgeUERadioCapabilityMatchResponseENBUES1APIDIEBindingFieldCodec(v *UERadioCapabilityMatchResponseENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUERadioCapabilityMatchResponseENBUES1APIDIEBindingFieldGet(v *UERadioCapabilityMatchResponseENBUES1APIDIEBinding) *func(*UERadioCapabilityMatchResponseIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUERadioCapabilityMatchResponseENBUES1APIDIEBindingFieldInfo(v *UERadioCapabilityMatchResponseENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUERadioCapabilityMatchResponseENBUES1APIDIEBindingFieldInject(v *UERadioCapabilityMatchResponseENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UERadioCapabilityMatchResponseIEValue {
	return &v.inject
}
func BridgeUERadioCapabilityMatchResponseIEContainerAPERValueFieldContext(v *UERadioCapabilityMatchResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEContainerAPERValueFieldReceived(v *UERadioCapabilityMatchResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseIEContainerAPERValueFieldReplay(v *UERadioCapabilityMatchResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseIEContainerAPERValueFieldWithoutReplay(v *UERadioCapabilityMatchResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *func(UERadioCapabilityMatchResponseIEContainer, aper.DecodeState) (UERadioCapabilityMatchResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *func(UERadioCapabilityMatchResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEContainer, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *func(UERadioCapabilityMatchResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecMethodEncodeBudgetValue(v UERadioCapabilityMatchResponseIEContainerValueCodec, a0 UERadioCapabilityMatchResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecMethodEncodeChanged(v UERadioCapabilityMatchResponseIEContainerValueCodec, a0 UERadioCapabilityMatchResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityMatchResponseIEFieldAPERValueFieldContext(v *UERadioCapabilityMatchResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEFieldAPERValueFieldReceived(v *UERadioCapabilityMatchResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseIEFieldAPERValueFieldReplay(v *UERadioCapabilityMatchResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseIEFieldAPERValueFieldWithoutReplay(v *UERadioCapabilityMatchResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseIEFieldFieldReceived(v *UERadioCapabilityMatchResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseIEFieldFieldReplay(v *UERadioCapabilityMatchResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseIEFieldFieldStream(v *UERadioCapabilityMatchResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUERadioCapabilityMatchResponseIEFieldFieldWithoutReplay(v *UERadioCapabilityMatchResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(v *UERadioCapabilityMatchResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(v *UERadioCapabilityMatchResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *func(UERadioCapabilityMatchResponseIEField, aper.DecodeState) (UERadioCapabilityMatchResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *func(UERadioCapabilityMatchResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEField, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *func(UERadioCapabilityMatchResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecMethodEncodeBudgetValue(v UERadioCapabilityMatchResponseIEFieldValueCodec, a0 UERadioCapabilityMatchResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecMethodEncodeChanged(v UERadioCapabilityMatchResponseIEFieldValueCodec, a0 UERadioCapabilityMatchResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityMatchResponseIETableMethodInfoCriticalityDiagnostics(v UERadioCapabilityMatchResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUERadioCapabilityMatchResponseIETableMethodInfoENBUES1APID(v UERadioCapabilityMatchResponseIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUERadioCapabilityMatchResponseIETableMethodInfoMMEUES1APID(v UERadioCapabilityMatchResponseIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUERadioCapabilityMatchResponseIETableMethodInfoVoiceSupportMatchIndicator(v UERadioCapabilityMatchResponseIETable) s00.FieldInfo {
	return v.infoVoiceSupportMatchIndicator()
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValueFieldContext(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValueFieldReceived(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValueFieldReplay(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec, a0 UERadioCapabilityMatchResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec, a0 UERadioCapabilityMatchResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldId(v *UERadioCapabilityMatchResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldIsOpaque(v *UERadioCapabilityMatchResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldOpaque(v *UERadioCapabilityMatchResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldReceived(v *UERadioCapabilityMatchResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldReplay(v *UERadioCapabilityMatchResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldRowCriticalityDiagnostics(v *UERadioCapabilityMatchResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldRowENBUES1APID(v *UERadioCapabilityMatchResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldRowMMEUES1APID(v *UERadioCapabilityMatchResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldRowVoiceSupportMatchIndicator(v *UERadioCapabilityMatchResponseIEValue) **s00.VoiceSupportMatchIndicator {
	return &v.rowVoiceSupportMatchIndicator
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodCaptureSemantics(v UERadioCapabilityMatchResponseIEValue, a0 aper.SemanticCapture) UERadioCapabilityMatchResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodCompareSemantics(v UERadioCapabilityMatchResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodDecode(v UERadioCapabilityMatchResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UERadioCapabilityMatchResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodEncode(v UERadioCapabilityMatchResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodEncodeFresh(v UERadioCapabilityMatchResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodMatchesID(v UERadioCapabilityMatchResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodReason(v UERadioCapabilityMatchResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodRule(v UERadioCapabilityMatchResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec, a0 UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec, a0 UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec, a0 UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec, a0 UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityMatchResponseMMEUES1APIDIEBindingFieldCodec(v *UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUERadioCapabilityMatchResponseMMEUES1APIDIEBindingFieldGet(v *UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) *func(*UERadioCapabilityMatchResponseIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUERadioCapabilityMatchResponseMMEUES1APIDIEBindingFieldInfo(v *UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUERadioCapabilityMatchResponseMMEUES1APIDIEBindingFieldInject(v *UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UERadioCapabilityMatchResponseIEValue {
	return &v.inject
}
func BridgeUERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBindingFieldCodec(v *UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) *s02.VoiceSupportMatchIndicatorValueCodec {
	return &v.codec
}
func BridgeUERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBindingFieldGet(v *UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) *func(*UERadioCapabilityMatchResponseIEValue) (*s00.VoiceSupportMatchIndicator, bool) {
	return &v.get
}
func BridgeUERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBindingFieldInfo(v *UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBindingFieldInject(v *UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) *func(s00.VoiceSupportMatchIndicator) UERadioCapabilityMatchResponseIEValue {
	return &v.inject
}
