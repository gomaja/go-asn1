// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s26 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s26

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
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
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// LocationReportingControlIEContainer is ProtocolIE-Container {{LocationReportingControlIEs}} of TS 36.413: a list of LocationReportingControlIEField values.
type LocationReportingControlIEContainer []LocationReportingControlIEField

// LocationReportingControlIEField is ProtocolIE-Field {{LocationReportingControlIEs}} of TS 36.413: an information element field.
type LocationReportingControlIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         LocationReportingControlIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingControlIEField) WithoutReplay() LocationReportingControlIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LocationReportingControlIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LocationReportingControlIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *LocationReportingControlIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LocationReportingControlIEField{}
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
	var zero LocationReportingControlIEValue

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
func BridgeLocationReportingControlIEValueCaptureS1APProtocolIEContainer(v *LocationReportingControlIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingControlIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportingControlIEValueCompareS1APProtocolIEContainer(v *LocationReportingControlIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingControlIEValueCompareS1APProtocolIEField(&(*v)[i], s)
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainer(v *s23.PathSwitchRequestFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainer(v *s23.PathSwitchRequestFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePrivateMessageIEsValueCaptureS1APPrivateIEContainer(v *s25.PrivateMessageIEsValuePrivateIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePrivateMessageIEsValueCaptureS1APPrivateIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePrivateMessageIEsValueCompareS1APPrivateIEContainer(v *s25.PrivateMessageIEsValuePrivateIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePrivateMessageIEsValueCompareS1APPrivateIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.RecommendedCellsForPagingItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.RecommendedCellsForPagingItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedCellItemIEValueCaptureS1APProtocolIESingleContainer(v *RecommendedCellItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRecommendedCellItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeRecommendedCellItemIEValueCompareS1APProtocolIESingleContainer(v *RecommendedCellItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRecommendedCellItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.RecommendedCellsForPagingExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.RecommendedCellsForPagingExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedENBItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.RecommendedENBItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedENBItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.RecommendedENBItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedENBsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.RecommendedENBsForPagingExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBsForPagingExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedENBsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.RecommendedENBsForPagingExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBsForPagingExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRequestTypeExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.RequestTypeExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRequestTypeExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRequestTypeExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.RequestTypeExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRequestTypeExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRequestedTNLInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.RequestedTNLInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRequestedTNLInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRequestedTNLInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.RequestedTNLInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRequestedTNLInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRerouteNASRequestIEValueCaptureS1APProtocolIEContainer(v *s20.RerouteNASRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRerouteNASRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// RecommendedCellItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{RecommendedCellItemIEs}} of TS 36.413: a single information element field.
type RecommendedCellItemIEValueProtocolIESingleContainer = RecommendedCellItemIEField

// RecommendedCellItemRecommendedCellItemIEBinding binds RecommendedCellItem to the RecommendedCellItemIEs object set of TS 36.413.
type RecommendedCellItemRecommendedCellItemIEBinding struct {
	info   s00.FieldInfo
	codec  RecommendedCellItemValueCodec
	inject func(RecommendedCellItem,

	) RecommendedCellItemIEValue

	get func(*RecommendedCellItemIEValue,

	) (*RecommendedCellItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RecommendedCellItemRecommendedCellItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RecommendedCellItemRecommendedCellItemIEBinding) Codec() RecommendedCellItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b RecommendedCellItemRecommendedCellItemIEBinding) New(value RecommendedCellItem,

) (RecommendedCellItemIEField, error) {
	if b.inject == nil {
		return RecommendedCellItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return RecommendedCellItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RecommendedCellItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return RecommendedCellItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RecommendedCellItemRecommendedCellItemIEBinding) Get(field *RecommendedCellItemIEField) (*RecommendedCellItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RecommendedCellItemValueCodec is the concrete ValueCodec[RecommendedCellItem].
type RecommendedCellItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellItem,

		error)
	encode func(RecommendedCellItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellItem, aper.DecodeState,

	) (RecommendedCellItem, aper.Snapshot,

	)
	compare func(RecommendedCellItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellItemValueCodec) New(value RecommendedCellItem,

) (RecommendedCellItemAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellItemValueCodec) EncodeAPER(value RecommendedCellItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedCellItemValueCodec) encodeBudgetValue(value RecommendedCellItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellItemValueCodec) encodeChanged(value RecommendedCellItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellItemIEField is ProtocolIE-Field {{RecommendedCellItemIEs}} of TS 36.413: an information element field.
type RecommendedCellItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         RecommendedCellItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellItemIEField) WithoutReplay() RecommendedCellItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedCellItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedCellItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *RecommendedCellItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellItemIEField{}
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
	var zero RecommendedCellItemIEValue

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

// RequestedTNLInfoValueCodec is the concrete ValueCodec[RequestedTNLInfo].
type RequestedTNLInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RequestedTNLInfo,

		error)
	encode func(RequestedTNLInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RequestedTNLInfo, aper.DecodeState,

	) (RequestedTNLInfo, aper.Snapshot,

	)
	compare func(RequestedTNLInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RequestedTNLInfoValueCodec) New(value RequestedTNLInfo,

) (RequestedTNLInfoAPERValue, error) {
	if c.encode == nil {
		return RequestedTNLInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestedTNLInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestedTNLInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RequestedTNLInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RequestedTNLInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestedTNLInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RequestedTNLInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RequestedTNLInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RequestedTNLInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RequestedTNLInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RequestedTNLInfoValueCodec) EncodeAPER(value RequestedTNLInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RequestedTNLInfoValueCodec) encodeBudgetValue(value RequestedTNLInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RequestedTNLInfoValueCodec) encodeChanged(value RequestedTNLInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RequestTypeValueCodec is the concrete ValueCodec[RequestType].
type RequestTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RequestType,

		error)
	encode func(RequestType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RequestType, aper.DecodeState,

	) (RequestType, aper.Snapshot,

	)
	compare func(RequestType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RequestTypeValueCodec) New(value RequestType,

) (RequestTypeAPERValue, error) {
	if c.encode == nil {
		return RequestTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RequestTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RequestTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RequestTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RequestTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RequestTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RequestTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RequestTypeValueCodec) EncodeAPER(value RequestTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RequestTypeValueCodec) encodeBudgetValue(value RequestType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RequestTypeValueCodec) encodeChanged(value RequestType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingControlMMEUES1APIDIEBinding binds MMEUES1APID to the LocationReportingControlIEs object set of TS 36.413.
type LocationReportingControlMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) LocationReportingControlIEValue

	get func(*LocationReportingControlIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportingControlMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingControlMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LocationReportingControlMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (LocationReportingControlIEField, error) {
	if b.inject == nil {
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportingControlIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportingControlMMEUES1APIDIEBinding) Get(field *LocationReportingControlIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportingControlENBUES1APIDIEBinding binds ENBUES1APID to the LocationReportingControlIEs object set of TS 36.413.
type LocationReportingControlENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) LocationReportingControlIEValue

	get func(*LocationReportingControlIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportingControlENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingControlENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LocationReportingControlENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (LocationReportingControlIEField, error) {
	if b.inject == nil {
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportingControlIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportingControlENBUES1APIDIEBinding) Get(field *LocationReportingControlIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportingControlRequestTypeIEBinding binds RequestType to the LocationReportingControlIEs object set of TS 36.413.
type LocationReportingControlRequestTypeIEBinding struct {
	info   s00.FieldInfo
	codec  RequestTypeValueCodec
	inject func(RequestType,

	) LocationReportingControlIEValue

	get func(*LocationReportingControlIEValue,

	) (*RequestType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportingControlRequestTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingControlRequestTypeIEBinding) Codec() RequestTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b LocationReportingControlRequestTypeIEBinding) New(value RequestType,

) (LocationReportingControlIEField, error) {
	if b.inject == nil {
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportingControlIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportingControlIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportingControlRequestTypeIEBinding) Get(field *LocationReportingControlIEField) (*RequestType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AssistanceDataForPagingValueCodec is the concrete ValueCodec[AssistanceDataForPaging].
type AssistanceDataForPagingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AssistanceDataForPaging,

		error)
	encode func(AssistanceDataForPaging,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AssistanceDataForPaging, aper.DecodeState,

	) (AssistanceDataForPaging, aper.Snapshot,

	)
	compare func(AssistanceDataForPaging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AssistanceDataForPagingValueCodec) New(value AssistanceDataForPaging,

) (AssistanceDataForPagingAPERValue, error) {
	if c.encode == nil {
		return AssistanceDataForPagingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceDataForPagingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceDataForPagingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AssistanceDataForPagingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AssistanceDataForPagingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceDataForPagingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AssistanceDataForPagingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AssistanceDataForPagingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AssistanceDataForPagingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AssistanceDataForPagingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AssistanceDataForPagingValueCodec) EncodeAPER(value AssistanceDataForPagingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceDataForPagingValueCodec) encodeBudgetValue(value AssistanceDataForPaging,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AssistanceDataForPagingValueCodec) encodeChanged(value AssistanceDataForPaging,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AssistanceDataForRecommendedCellsValueCodec is the concrete ValueCodec[AssistanceDataForRecommendedCells].
type AssistanceDataForRecommendedCellsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AssistanceDataForRecommendedCells,

		error)
	encode func(AssistanceDataForRecommendedCells,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AssistanceDataForRecommendedCells, aper.DecodeState,

	) (AssistanceDataForRecommendedCells, aper.Snapshot,

	)
	compare func(AssistanceDataForRecommendedCells, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AssistanceDataForRecommendedCellsValueCodec) New(value AssistanceDataForRecommendedCells,

) (AssistanceDataForRecommendedCellsAPERValue, error) {
	if c.encode == nil {
		return AssistanceDataForRecommendedCellsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceDataForRecommendedCellsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceDataForRecommendedCellsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AssistanceDataForRecommendedCellsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AssistanceDataForRecommendedCellsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceDataForRecommendedCellsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AssistanceDataForRecommendedCellsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AssistanceDataForRecommendedCellsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AssistanceDataForRecommendedCellsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AssistanceDataForRecommendedCellsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AssistanceDataForRecommendedCellsValueCodec) EncodeAPER(value AssistanceDataForRecommendedCellsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceDataForRecommendedCellsValueCodec) encodeBudgetValue(value AssistanceDataForRecommendedCells,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AssistanceDataForRecommendedCellsValueCodec) encodeChanged(value AssistanceDataForRecommendedCells,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingControlValueCodec is the concrete ValueCodec[LocationReportingControl].
type LocationReportingControlValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingControl,

		error)
	encode func(LocationReportingControl,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingControl, aper.DecodeState,

	) (LocationReportingControl, aper.Snapshot,

	)
	compare func(LocationReportingControl, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingControlValueCodec) New(value LocationReportingControl,

) (LocationReportingControlAPERValue, error) {
	if c.encode == nil {
		return LocationReportingControlAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingControlAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingControlAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingControlValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingControlAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingControlAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingControlAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingControlAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingControlAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingControlValueCodec) EncodeAPER(value LocationReportingControlAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingControlValueCodec) encodeBudgetValue(value LocationReportingControl,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingControlValueCodec) encodeChanged(value LocationReportingControl,

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

// PathSwitchRequestFailureValueCodec is the concrete ValueCodec[PathSwitchRequestFailure].
type PathSwitchRequestFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestFailure,

		error)
	encode func(PathSwitchRequestFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestFailure, aper.DecodeState,

	) (PathSwitchRequestFailure, aper.Snapshot,

	)
	compare func(PathSwitchRequestFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestFailureValueCodec) New(value PathSwitchRequestFailure,

) (PathSwitchRequestFailureAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestFailureValueCodec) EncodeAPER(value PathSwitchRequestFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestFailureValueCodec) encodeBudgetValue(value PathSwitchRequestFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestFailureValueCodec) encodeChanged(value PathSwitchRequestFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PrivateMessageValueCodec is the concrete ValueCodec[PrivateMessage].
type PrivateMessageValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PrivateMessage,

		error)
	encode func(PrivateMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PrivateMessage, aper.DecodeState,

	) (PrivateMessage, aper.Snapshot,

	)
	compare func(PrivateMessage, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PrivateMessageValueCodec) New(value PrivateMessage,

) (PrivateMessageAPERValue, error) {
	if c.encode == nil {
		return PrivateMessageAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivateMessageAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PrivateMessageAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PrivateMessageValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PrivateMessageAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PrivateMessageAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PrivateMessageAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PrivateMessageAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PrivateMessageAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PrivateMessageValueCodec) EncodeAPER(value PrivateMessageAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PrivateMessageValueCodec) encodeBudgetValue(value PrivateMessage,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PrivateMessageValueCodec) encodeChanged(value PrivateMessage,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellListValueCodec is the concrete ValueCodec[RecommendedCellList].
type RecommendedCellListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellList,

		error)
	encode func(RecommendedCellList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellList, aper.DecodeState,

	) (RecommendedCellList, aper.Snapshot,

	)
	compare func(RecommendedCellList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellListValueCodec) New(value RecommendedCellList,

) (RecommendedCellListAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellListValueCodec) EncodeAPER(value RecommendedCellListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedCellListValueCodec) encodeBudgetValue(value RecommendedCellList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellListValueCodec) encodeChanged(value RecommendedCellList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellsForPagingValueCodec is the concrete ValueCodec[RecommendedCellsForPaging].
type RecommendedCellsForPagingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellsForPaging,

		error)
	encode func(RecommendedCellsForPaging,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellsForPaging, aper.DecodeState,

	) (RecommendedCellsForPaging, aper.Snapshot,

	)
	compare func(RecommendedCellsForPaging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellsForPagingValueCodec) New(value RecommendedCellsForPaging,

) (RecommendedCellsForPagingAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellsForPagingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellsForPagingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellsForPagingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellsForPagingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellsForPagingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellsForPagingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellsForPagingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellsForPagingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellsForPagingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellsForPagingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellsForPagingValueCodec) EncodeAPER(value RecommendedCellsForPagingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedCellsForPagingValueCodec) encodeBudgetValue(value RecommendedCellsForPaging,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellsForPagingValueCodec) encodeChanged(value RecommendedCellsForPaging,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellItemIEContainer is ProtocolIE-Container {{RecommendedCellItemIEs}} of TS 36.413: a list of RecommendedCellItemIEField values.
type RecommendedCellItemIEContainer []RecommendedCellItemIEField

// LocationReportingControlIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{LocationReportingControlIEs}} codec of TS 36.413.
func LocationReportingControlIEValueERABIEContainerListCodec(table s00.LocationReportingControlIEValueIETable) LocationReportingControlIEValueERABIEContainerListValueCodec {
	codec := LocationReportingControlIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return LocationReportingControlIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return LocationReportingControlIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (LocationReportingControlIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields LocationReportingControlIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field LocationReportingControlIEField
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
			return nil, runtime.WrapDecodePath(err, "LocationReportingControlIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "LocationReportingControlIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "LocationReportingControlIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value LocationReportingControlIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(LocationReportingControlIEContainer(value), fresh, budget)
	}, capture: func(v LocationReportingControlIEValueERABIEContainerList, options aper.DecodeState) (LocationReportingControlIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeLocationReportingControlIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v LocationReportingControlIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeLocationReportingControlIEValueCompareS1APERABIEContainerList(&v, &s)
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

// MMEConfigurationUpdateFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueERABIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable) s23.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.MMEConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s23.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s22.MMEStatusTransferIEValueERABIEContainerListValueCodec {
		sealed := s22.MMEStatusTransferIEValueERABIEContainerListValueCodec{}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEStatusTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.MMEStatusTransferIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.MMEStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEStatusTransferIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEStatusTransferIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEStatusTransferIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.MMEStatusTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&codec))(s22.MMEStatusTransferIEContainer(value), fresh, budget)
		}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.MMEStatusTransferIEValueERABIEContainerList, options aper.DecodeState) (s22.MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s22.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.MMEStatusTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec {
		sealed := s19.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec{}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.NASNonDeliveryIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.NASNonDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASNonDeliveryIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s19.NASNonDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s19.NASNonDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueERABIEContainerList, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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

// PathSwitchRequestFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PathSwitchRequestFailureIEs}} codec of TS 36.413.
func PathSwitchRequestFailureIEValueERABIEContainerListCodec(table s00.PathSwitchRequestFailureIEValueIETable) s23.PathSwitchRequestFailureIEValueERABIEContainerListValueCodec {
	codec := PathSwitchRequestFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.PathSwitchRequestFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.PathSwitchRequestFailureIEValueERABIEContainerListValueCodec {
		sealed := s23.PathSwitchRequestFailureIEValueERABIEContainerListValueCodec{}
		*s23.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PathSwitchRequestFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.PathSwitchRequestFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.PathSwitchRequestFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.PathSwitchRequestFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(&codec))(s23.PathSwitchRequestFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.PathSwitchRequestFailureIEValueERABIEContainerList, options aper.DecodeState) (s23.PathSwitchRequestFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.PathSwitchRequestFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{RecommendedCellItemIEs}} codec of TS 36.413.
func RecommendedCellItemIEValueERABIEContainerListCodec(table s00.RecommendedCellItemIEValueIETable) RecommendedCellItemIEValueERABIEContainerListValueCodec {
	codec := RecommendedCellItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return RecommendedCellItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return RecommendedCellItemIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (RecommendedCellItemIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields RecommendedCellItemIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field RecommendedCellItemIEField
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
			return nil, runtime.WrapDecodePath(err, "RecommendedCellItemIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "RecommendedCellItemIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "RecommendedCellItemIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value RecommendedCellItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(RecommendedCellItemIEContainer(value), fresh, budget)
	}, capture: func(v RecommendedCellItemIEValueERABIEContainerList, options aper.DecodeState) (RecommendedCellItemIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeRecommendedCellItemIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v RecommendedCellItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeRecommendedCellItemIEValueCompareS1APERABIEContainerList(&v, &s)
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

// RecommendedCellsForPagingExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RecommendedCellsForPaging-ExtIEs}} codec of TS 36.413.
func RecommendedCellsForPagingExtIEsValueExtensionFieldTableCodec(table s00.RecommendedCellsForPagingExtIEsValueExtensionTable) s11.RecommendedCellsForPagingExtIEsExtFieldValueCodec {
	if !*s00.BridgeRecommendedCellsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RecommendedCellsForPagingExtIEsExtFieldValueCodec{}
	}
	return func() s11.RecommendedCellsForPagingExtIEsExtFieldValueCodec {
		sealed := s11.RecommendedCellsForPagingExtIEsExtFieldValueCodec{}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RecommendedCellsForPagingExtIEsExtField, error) {
			var field s11.RecommendedCellsForPagingExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedCellsForPagingExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedCellsForPagingExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedCellsForPagingExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.RecommendedCellsForPagingExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.RecommendedCellsForPagingExtIEsExtField, options aper.DecodeState) (s11.RecommendedCellsForPagingExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.RecommendedCellsForPagingExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellsForPagingItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RecommendedCellsForPagingItem-ExtIEs}} codec of TS 36.413.
func RecommendedCellsForPagingItemExtIEsValueExtensionFieldTableCodec(table s00.RecommendedCellsForPagingItemExtIEsValueExtensionTable) s11.RecommendedCellsForPagingItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeRecommendedCellsForPagingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RecommendedCellsForPagingItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.RecommendedCellsForPagingItemExtIEsExtFieldValueCodec {
		sealed := s11.RecommendedCellsForPagingItemExtIEsExtFieldValueCodec{}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RecommendedCellsForPagingItemExtIEsExtField, error) {
			var field s11.RecommendedCellsForPagingItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedCellsForPagingItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedCellsForPagingItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedCellsForPagingItemExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.RecommendedCellsForPagingItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.RecommendedCellsForPagingItemExtIEsExtField, options aper.DecodeState) (s11.RecommendedCellsForPagingItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.RecommendedCellsForPagingItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedENBItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RecommendedENBItem-ExtIEs}} codec of TS 36.413.
func RecommendedENBItemExtIEsValueExtensionFieldTableCodec(table s00.RecommendedENBItemExtIEsValueExtensionTable) s11.RecommendedENBItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeRecommendedENBItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RecommendedENBItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.RecommendedENBItemExtIEsExtFieldValueCodec {
		sealed := s11.RecommendedENBItemExtIEsExtFieldValueCodec{}
		*s11.BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RecommendedENBItemExtIEsExtField, error) {
			var field s11.RecommendedENBItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeRecommendedENBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedENBItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedENBItemExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.RecommendedENBItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeRecommendedENBItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.RecommendedENBItemExtIEsExtField, options aper.DecodeState) (s11.RecommendedENBItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.RecommendedENBItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRecommendedENBItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedENBsForPagingExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RecommendedENBsForPaging-ExtIEs}} codec of TS 36.413.
func RecommendedENBsForPagingExtIEsValueExtensionFieldTableCodec(table s00.RecommendedENBsForPagingExtIEsValueExtensionTable) s11.RecommendedENBsForPagingExtIEsExtFieldValueCodec {
	if !*s00.BridgeRecommendedENBsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RecommendedENBsForPagingExtIEsExtFieldValueCodec{}
	}
	return func() s11.RecommendedENBsForPagingExtIEsExtFieldValueCodec {
		sealed := s11.RecommendedENBsForPagingExtIEsExtFieldValueCodec{}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RecommendedENBsForPagingExtIEsExtField, error) {
			var field s11.RecommendedENBsForPagingExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeRecommendedENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedENBsForPagingExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBsForPagingExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedENBsForPagingExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.RecommendedENBsForPagingExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeRecommendedENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.RecommendedENBsForPagingExtIEsExtField, options aper.DecodeState) (s11.RecommendedENBsForPagingExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBsForPagingExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.RecommendedENBsForPagingExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRecommendedENBsForPagingExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RequestTypeExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RequestType-ExtIEs}} codec of TS 36.413.
func RequestTypeExtIEsValueExtensionFieldTableCodec(table s00.RequestTypeExtIEsValueExtensionTable) s11.RequestTypeExtIEsExtFieldValueCodec {
	if !*s00.BridgeRequestTypeExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RequestTypeExtIEsExtFieldValueCodec{}
	}
	return func() s11.RequestTypeExtIEsExtFieldValueCodec {
		sealed := s11.RequestTypeExtIEsExtFieldValueCodec{}
		*s11.BridgeRequestTypeExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RequestTypeExtIEsExtField, error) {
			var field s11.RequestTypeExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeRequestTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RequestTypeExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RequestTypeExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RequestTypeExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeRequestTypeExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.RequestTypeExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeRequestTypeExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeRequestTypeExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.RequestTypeExtIEsExtField, options aper.DecodeState) (s11.RequestTypeExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRequestTypeExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeRequestTypeExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.RequestTypeExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRequestTypeExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRequestTypeExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RequestedTNLInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RequestedTNLInfo-ExtIEs}} codec of TS 36.413.
func RequestedTNLInfoExtIEsValueExtensionFieldTableCodec(table s00.RequestedTNLInfoExtIEsValueExtensionTable) s11.RequestedTNLInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeRequestedTNLInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RequestedTNLInfoExtIEsExtFieldValueCodec{}
	}
	return func() s11.RequestedTNLInfoExtIEsExtFieldValueCodec {
		sealed := s11.RequestedTNLInfoExtIEsExtFieldValueCodec{}
		*s11.BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RequestedTNLInfoExtIEsExtField, error) {
			var field s11.RequestedTNLInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeRequestedTNLInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RequestedTNLInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RequestedTNLInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RequestedTNLInfoExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.RequestedTNLInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeRequestedTNLInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.RequestedTNLInfoExtIEsExtField, options aper.DecodeState) (s11.RequestedTNLInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRequestedTNLInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.RequestedTNLInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRequestedTNLInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellsForPagingExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RecommendedCellsForPaging-ExtIEs}} codec of TS 36.413.
func RecommendedCellsForPagingExtIEsValueExtensionTableCodec(table s00.RecommendedCellsForPagingExtIEsValueExtensionTable, bounds aper.ListBounds) s11.RecommendedCellsForPagingExtIEsExtContainerValueCodec {
	if !*s00.BridgeRecommendedCellsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RecommendedCellsForPagingExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.RecommendedCellsForPagingExtIEsExtContainerValueCodec {
		sealed := s11.RecommendedCellsForPagingExtIEsExtContainerValueCodec{}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RecommendedCellsForPagingExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.RecommendedCellsForPagingExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.RecommendedCellsForPagingExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RecommendedCellsForPagingExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedCellsForPagingExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RecommendedCellsForPagingExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.RecommendedCellsForPagingExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.RecommendedCellsForPagingExtIEsExtContainer, options aper.DecodeState) (s11.RecommendedCellsForPagingExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.RecommendedCellsForPagingExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellsForPagingItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RecommendedCellsForPagingItem-ExtIEs}} codec of TS 36.413.
func RecommendedCellsForPagingItemExtIEsValueExtensionTableCodec(table s00.RecommendedCellsForPagingItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.RecommendedCellsForPagingItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeRecommendedCellsForPagingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RecommendedCellsForPagingItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.RecommendedCellsForPagingItemExtIEsExtContainerValueCodec {
		sealed := s11.RecommendedCellsForPagingItemExtIEsExtContainerValueCodec{}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RecommendedCellsForPagingItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.RecommendedCellsForPagingItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.RecommendedCellsForPagingItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RecommendedCellsForPagingItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedCellsForPagingItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RecommendedCellsForPagingItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.RecommendedCellsForPagingItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.RecommendedCellsForPagingItemExtIEsExtContainer, options aper.DecodeState) (s11.RecommendedCellsForPagingItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.RecommendedCellsForPagingItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RecommendedENBItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RecommendedENBItem-ExtIEs}} codec of TS 36.413.
func RecommendedENBItemExtIEsValueExtensionTableCodec(table s00.RecommendedENBItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.RecommendedENBItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeRecommendedENBItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RecommendedENBItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.RecommendedENBItemExtIEsExtContainerValueCodec {
		sealed := s11.RecommendedENBItemExtIEsExtContainerValueCodec{}
		*s11.BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RecommendedENBItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.RecommendedENBItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.RecommendedENBItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeRecommendedENBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.RecommendedENBItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeRecommendedENBItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.RecommendedENBItemExtIEsExtContainer, options aper.DecodeState) (s11.RecommendedENBItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.RecommendedENBItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RecommendedENBsForPagingExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RecommendedENBsForPaging-ExtIEs}} codec of TS 36.413.
func RecommendedENBsForPagingExtIEsValueExtensionTableCodec(table s00.RecommendedENBsForPagingExtIEsValueExtensionTable, bounds aper.ListBounds) s11.RecommendedENBsForPagingExtIEsExtContainerValueCodec {
	if !*s00.BridgeRecommendedENBsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RecommendedENBsForPagingExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.RecommendedENBsForPagingExtIEsExtContainerValueCodec {
		sealed := s11.RecommendedENBsForPagingExtIEsExtContainerValueCodec{}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RecommendedENBsForPagingExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.RecommendedENBsForPagingExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.RecommendedENBsForPagingExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeRecommendedENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RecommendedENBsForPagingExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBsForPagingExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RecommendedENBsForPagingExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.RecommendedENBsForPagingExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeRecommendedENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.RecommendedENBsForPagingExtIEsExtContainer, options aper.DecodeState) (s11.RecommendedENBsForPagingExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.RecommendedENBsForPagingExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RequestTypeExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RequestType-ExtIEs}} codec of TS 36.413.
func RequestTypeExtIEsValueExtensionTableCodec(table s00.RequestTypeExtIEsValueExtensionTable, bounds aper.ListBounds) s11.RequestTypeExtIEsExtContainerValueCodec {
	if !*s00.BridgeRequestTypeExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RequestTypeExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.RequestTypeExtIEsExtContainerValueCodec {
		sealed := s11.RequestTypeExtIEsExtContainerValueCodec{}
		*s11.BridgeRequestTypeExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RequestTypeExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.RequestTypeExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.RequestTypeExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeRequestTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RequestTypeExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RequestTypeExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RequestTypeExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeRequestTypeExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.RequestTypeExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeRequestTypeExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeRequestTypeExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.RequestTypeExtIEsExtContainer, options aper.DecodeState) (s11.RequestTypeExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRequestTypeExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeRequestTypeExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.RequestTypeExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRequestTypeExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRequestTypeExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RequestedTNLInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RequestedTNLInfo-ExtIEs}} codec of TS 36.413.
func RequestedTNLInfoExtIEsValueExtensionTableCodec(table s00.RequestedTNLInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s11.RequestedTNLInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeRequestedTNLInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.RequestedTNLInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.RequestedTNLInfoExtIEsExtContainerValueCodec {
		sealed := s11.RequestedTNLInfoExtIEsExtContainerValueCodec{}
		*s11.BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.RequestedTNLInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.RequestedTNLInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.RequestedTNLInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeRequestedTNLInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RequestedTNLInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RequestedTNLInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RequestedTNLInfoExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.RequestedTNLInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeRequestedTNLInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.RequestedTNLInfoExtIEsExtContainer, options aper.DecodeState) (s11.RequestedTNLInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRequestedTNLInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.RequestedTNLInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRequestedTNLInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingControlIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{LocationReportingControlIEs}} codec of TS 36.413.
func LocationReportingControlIEValueIEFieldTableCodec(table s00.LocationReportingControlIEValueIETable) LocationReportingControlIEFieldValueCodec {
	if !*s00.BridgeLocationReportingControlIEValueIETableFieldBound(&table) {
		return LocationReportingControlIEFieldValueCodec{}
	}
	return LocationReportingControlIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (LocationReportingControlIEField, error) {
		var field LocationReportingControlIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "LocationReportingControlIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "LocationReportingControlIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "LocationReportingControlIEField")
		}
		return field, nil
	}, encode: func(field LocationReportingControlIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v LocationReportingControlIEField, options aper.DecodeState) (LocationReportingControlIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeLocationReportingControlIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v LocationReportingControlIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeLocationReportingControlIEValueCompareS1APProtocolIEField(&v, &s)
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
				return field, runtime.WrapDecodePath(err, "MMEStatusTransferIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEStatusTransferIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEStatusTransferIEField")
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
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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
				return field, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASNonDeliveryIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEField")
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
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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

// PathSwitchRequestFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PathSwitchRequestFailureIEs}} codec of TS 36.413.
func PathSwitchRequestFailureIEValueIEFieldTableCodec(table s00.PathSwitchRequestFailureIEValueIETable) s23.PathSwitchRequestFailureIEFieldValueCodec {
	if !*s00.BridgePathSwitchRequestFailureIEValueIETableFieldBound(&table) {
		return s23.PathSwitchRequestFailureIEFieldValueCodec{}
	}
	return func() s23.PathSwitchRequestFailureIEFieldValueCodec {
		sealed := s23.PathSwitchRequestFailureIEFieldValueCodec{}
		*s23.BridgePathSwitchRequestFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PathSwitchRequestFailureIEField, error) {
			var field s23.PathSwitchRequestFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEField")
			}
			return field, nil
		}
		*s23.BridgePathSwitchRequestFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s23.PathSwitchRequestFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgePathSwitchRequestFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s23.PathSwitchRequestFailureIEField, options aper.DecodeState) (s23.PathSwitchRequestFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgePathSwitchRequestFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s23.PathSwitchRequestFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgePathSwitchRequestFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{RecommendedCellItemIEs}} codec of TS 36.413.
func RecommendedCellItemIEValueIEFieldTableCodec(table s00.RecommendedCellItemIEValueIETable) RecommendedCellItemIEFieldValueCodec {
	if !*s00.BridgeRecommendedCellItemIEValueIETableFieldBound(&table) {
		return RecommendedCellItemIEFieldValueCodec{}
	}
	return RecommendedCellItemIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (RecommendedCellItemIEField, error) {
		var field RecommendedCellItemIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "RecommendedCellItemIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "RecommendedCellItemIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "RecommendedCellItemIEField")
		}
		return field, nil
	}, encode: func(field RecommendedCellItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v RecommendedCellItemIEField, options aper.DecodeState) (RecommendedCellItemIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeRecommendedCellItemIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v RecommendedCellItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeRecommendedCellItemIEValueCompareS1APProtocolIEField(&v, &s)
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

// LocationReportingControlIEValueIETableCodec constructs the ProtocolIE-Container {{LocationReportingControlIEs}} codec of TS 36.413.
func LocationReportingControlIEValueIETableCodec(table s00.LocationReportingControlIEValueIETable, bounds aper.ListBounds) LocationReportingControlIEContainerValueCodec {
	if !*s00.BridgeLocationReportingControlIEValueIETableFieldBound(&table) {
		return LocationReportingControlIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return LocationReportingControlIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (LocationReportingControlIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields LocationReportingControlIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field LocationReportingControlIEField
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
			return nil, runtime.WrapDecodePath(err, "LocationReportingControlIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "LocationReportingControlIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "LocationReportingControlIEContainer")
		}
		return fields, nil
	},
		encode: func(fields LocationReportingControlIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v LocationReportingControlIEContainer, options aper.DecodeState) (LocationReportingControlIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingControlIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v LocationReportingControlIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingControlIEValueCompareS1APProtocolIEContainer(&v, &s)
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateFailureIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEContainer")
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
			s25.BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEStatusTransferIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEStatusTransferIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEStatusTransferIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s22.BridgeMMEStatusTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s22.MMEStatusTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASNonDeliveryIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s19.NASNonDeliveryIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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

// PathSwitchRequestFailureIEValueIETableCodec constructs the ProtocolIE-Container {{PathSwitchRequestFailureIEs}} codec of TS 36.413.
func PathSwitchRequestFailureIEValueIETableCodec(table s00.PathSwitchRequestFailureIEValueIETable, bounds aper.ListBounds) s23.PathSwitchRequestFailureIEContainerValueCodec {
	if !*s00.BridgePathSwitchRequestFailureIEValueIETableFieldBound(&table) {
		return s23.PathSwitchRequestFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.PathSwitchRequestFailureIEContainerValueCodec {
		sealed := s23.PathSwitchRequestFailureIEContainerValueCodec{}
		*s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PathSwitchRequestFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.PathSwitchRequestFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.PathSwitchRequestFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestFailureIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEContainer")
			}
			return fields, nil
		}
		*s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.PathSwitchRequestFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s23.PathSwitchRequestFailureIEContainer, options aper.DecodeState) (s23.PathSwitchRequestFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s23.PathSwitchRequestFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellItemIEValueIETableCodec constructs the ProtocolIE-Container {{RecommendedCellItemIEs}} codec of TS 36.413.
func RecommendedCellItemIEValueIETableCodec(table s00.RecommendedCellItemIEValueIETable, bounds aper.ListBounds) RecommendedCellItemIEContainerValueCodec {
	if !*s00.BridgeRecommendedCellItemIEValueIETableFieldBound(&table) {
		return RecommendedCellItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return RecommendedCellItemIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (RecommendedCellItemIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields RecommendedCellItemIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field RecommendedCellItemIEField
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
			return nil, runtime.WrapDecodePath(err, "RecommendedCellItemIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "RecommendedCellItemIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "RecommendedCellItemIEContainer")
		}
		return fields, nil
	},
		encode: func(fields RecommendedCellItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v RecommendedCellItemIEContainer, options aper.DecodeState) (RecommendedCellItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v RecommendedCellItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedCellItemIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// PrivateMessageIEsValuePrivateFieldTableCodec constructs the PrivateIE-Field {{PrivateMessageIEs}} codec of TS 36.413.
func PrivateMessageIEsValuePrivateFieldTableCodec(table s00.PrivateMessageIEsValuePrivateTable) s25.PrivateMessageIEsValuePrivateIEFieldValueCodec {
	if !*s00.BridgePrivateMessageIEsValuePrivateTableFieldBound(&table) {
		return s25.PrivateMessageIEsValuePrivateIEFieldValueCodec{}
	}
	return func() s25.PrivateMessageIEsValuePrivateIEFieldValueCodec {
		sealed := s25.PrivateMessageIEsValuePrivateIEFieldValueCodec{}
		*s25.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.PrivateMessageIEsValuePrivateIEField, error) {
			var field s25.PrivateMessageIEsValuePrivateIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s25.BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PrivateMessageIEsValuePrivateIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PrivateMessageIEsValuePrivateIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PrivateMessageIEsValuePrivateIEField")
			}
			return field, nil
		}
		*s25.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldEncode(&sealed) = func(field s25.PrivateMessageIEsValuePrivateIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s25.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s25.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldCapture(&sealed) = func(v s25.PrivateMessageIEsValuePrivateIEField, options aper.DecodeState) (s25.PrivateMessageIEsValuePrivateIEField, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePrivateMessageIEsValueCaptureS1APPrivateIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s25.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldCompare(&sealed) = func(v s25.PrivateMessageIEsValuePrivateIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePrivateMessageIEsValueCompareS1APPrivateIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PrivateMessageIEsValuePrivateTableCodec constructs the PrivateIE-Container {{PrivateMessageIEs}} codec of TS 36.413.
func PrivateMessageIEsValuePrivateTableCodec(table s00.PrivateMessageIEsValuePrivateTable, bounds aper.ListBounds) s25.PrivateMessageIEsValuePrivateIEContainerValueCodec {
	if !*s00.BridgePrivateMessageIEsValuePrivateTableFieldBound(&table) {
		return s25.PrivateMessageIEsValuePrivateIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s25.PrivateMessageIEsValuePrivateIEContainerValueCodec {
		sealed := s25.PrivateMessageIEsValuePrivateIEContainerValueCodec{}
		*s25.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.PrivateMessageIEsValuePrivateIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.PrivateMessageIEsValuePrivateIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.PrivateMessageIEsValuePrivateIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PrivateMessageIEsValuePrivateIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PrivateMessageIEsValuePrivateIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PrivateMessageIEsValuePrivateIEContainer")
			}
			return fields, nil
		}
		*s25.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldEncode(&sealed) = func(fields s25.PrivateMessageIEsValuePrivateIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s25.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s25.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldCapture(&sealed) = func(v s25.PrivateMessageIEsValuePrivateIEContainer, options aper.DecodeState) (s25.PrivateMessageIEsValuePrivateIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePrivateMessageIEsValueCaptureS1APPrivateIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*s25.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldCompare(&sealed) = func(v s25.PrivateMessageIEsValuePrivateIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePrivateMessageIEsValueCompareS1APPrivateIEContainer(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingControlIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{LocationReportingControlIEs}} codec of TS 36.413.
func LocationReportingControlIEValueProtocolErrorIEContainerListCodec(table s00.LocationReportingControlIEValueIETable) LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec {
	codec := LocationReportingControlIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (LocationReportingControlIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields LocationReportingControlIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field LocationReportingControlIEField
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
			return nil, runtime.WrapDecodePath(err, "LocationReportingControlIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "LocationReportingControlIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "LocationReportingControlIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value LocationReportingControlIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(LocationReportingControlIEContainer(value), fresh, budget)
	}, capture: func(v LocationReportingControlIEValueProtocolErrorIEContainerList, options aper.DecodeState) (LocationReportingControlIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeLocationReportingControlIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v LocationReportingControlIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeLocationReportingControlIEValueCompareS1APProtocolErrorIEContainerList(
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

// MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable) s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.MMEConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s23.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s22.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEStatusTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.MMEStatusTransferIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.MMEStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEStatusTransferIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEStatusTransferIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEStatusTransferIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.NASNonDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// PathSwitchRequestFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PathSwitchRequestFailureIEs}} codec of TS 36.413.
func PathSwitchRequestFailureIEValueProtocolErrorIEContainerListCodec(table s00.PathSwitchRequestFailureIEValueIETable) s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := PathSwitchRequestFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.PathSwitchRequestFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestFailureIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(&codec))(s23.PathSwitchRequestFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{RecommendedCellItemIEs}} codec of TS 36.413.
func RecommendedCellItemIEValueProtocolErrorIEContainerListCodec(table s00.RecommendedCellItemIEValueIETable) RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := RecommendedCellItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (RecommendedCellItemIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields RecommendedCellItemIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field RecommendedCellItemIEField
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
			return nil, runtime.WrapDecodePath(err, "RecommendedCellItemIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "RecommendedCellItemIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "RecommendedCellItemIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value RecommendedCellItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(RecommendedCellItemIEContainer(value), fresh, budget)
	}, capture: func(v RecommendedCellItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (RecommendedCellItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeRecommendedCellItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v RecommendedCellItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeRecommendedCellItemIEValueCompareS1APProtocolErrorIEContainerList(
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

// LocationReportingControlIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {LocationReportingControlIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func LocationReportingControlIEValueProtocolIEContainerListCodec(table s00.LocationReportingControlIEValueIETable, bounds aper.ListBounds) LocationReportingControlIEValueProtocolIEContainerListValueCodec {
	codec := LocationReportingControlIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return LocationReportingControlIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return LocationReportingControlIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (LocationReportingControlIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields LocationReportingControlIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field LocationReportingControlIEField
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
			return nil, runtime.WrapDecodePath(err, "LocationReportingControlIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "LocationReportingControlIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "LocationReportingControlIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value LocationReportingControlIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(LocationReportingControlIEContainer(value), fresh, budget)
	}, capture: func(v LocationReportingControlIEValueProtocolIEContainerList, options aper.DecodeState) (LocationReportingControlIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeLocationReportingControlIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v LocationReportingControlIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeLocationReportingControlIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// MMEConfigurationUpdateFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationUpdateFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEConfigurationUpdateFailureIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, bounds)
	if *s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.MMEConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateFailureIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s23.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s23.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s22.MMEStatusTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s22.MMEStatusTransferIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.MMEStatusTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.MMEStatusTransferIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.MMEStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEStatusTransferIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEStatusTransferIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEStatusTransferIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s22.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.MMEStatusTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s19.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s19.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s19.NASNonDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASNonDeliveryIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s19.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s19.NASNonDeliveryIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// PathSwitchRequestFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PathSwitchRequestFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PathSwitchRequestFailureIEValueProtocolIEContainerListCodec(table s00.PathSwitchRequestFailureIEValueIETable, bounds aper.ListBounds) s23.PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec {
	codec := PathSwitchRequestFailureIEValueIETableCodec(table, bounds)
	if *s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s23.PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s23.PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PathSwitchRequestFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.PathSwitchRequestFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.PathSwitchRequestFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestFailureIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.PathSwitchRequestFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(&codec))(s23.PathSwitchRequestFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.PathSwitchRequestFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s23.PathSwitchRequestFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.PathSwitchRequestFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {RecommendedCellItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func RecommendedCellItemIEValueProtocolIEContainerListCodec(table s00.RecommendedCellItemIEValueIETable, bounds aper.ListBounds) RecommendedCellItemIEValueProtocolIEContainerListValueCodec {
	codec := RecommendedCellItemIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return RecommendedCellItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return RecommendedCellItemIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (RecommendedCellItemIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields RecommendedCellItemIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field RecommendedCellItemIEField
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
			return nil, runtime.WrapDecodePath(err, "RecommendedCellItemIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "RecommendedCellItemIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "RecommendedCellItemIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value RecommendedCellItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(RecommendedCellItemIEContainer(value), fresh, budget)
	}, capture: func(v RecommendedCellItemIEValueProtocolIEContainerList, options aper.DecodeState) (RecommendedCellItemIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeRecommendedCellItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v RecommendedCellItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeRecommendedCellItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// locationReportingControlIEValueProtocolOpenValue is the concrete protocolOpenValue[LocationReportingControlIEValue].
type LocationReportingControlIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) LocationReportingControlIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (LocationReportingControlIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLocationReportingControlIEValueCaptureS1APProtocolIEField(v *LocationReportingControlIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeLocationReportingControlIEValueCompareS1APProtocolIEField(v *LocationReportingControlIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
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

// mMEStatusTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEStatusTransferIEValue].
type MMEStatusTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.MMEStatusTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.MMEStatusTransferIEValue,

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
	v.Value = s22.BridgeMMEStatusTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeMMEStatusTransferIEFieldFieldReplay(v), *s22.BridgeMMEStatusTransferIEFieldFieldWithoutReplay(v))
}
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIEField(v *s22.MMEStatusTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeMMEStatusTransferIEValueMethodCompareSemantics(v.Value, *s)
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

// pathSwitchRequestFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s23.PathSwitchRequestFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s23.PathSwitchRequestFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEField(v *s23.PathSwitchRequestFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgePathSwitchRequestFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgePathSwitchRequestFailureIEFieldFieldReplay(v), *s23.BridgePathSwitchRequestFailureIEFieldFieldWithoutReplay(v))
}
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEField(v *s23.PathSwitchRequestFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgePathSwitchRequestFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgePathSwitchRequestFailureIEFieldFieldReplay(v), *s23.BridgePathSwitchRequestFailureIEFieldFieldWithoutReplay(v))
}

// privateMessageIEsValueProtocolPrivateValue is the concrete protocolPrivateValue[PrivateMessageIEsValue].
type PrivateMessageIEsValueProtocolPrivateValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s25.PrivateMessageIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	matchesID(s20.PrivateIEID, ...*aper.DecodeBudget) bool
	decode(s20.PrivateIEID, aper.OpaqueOpenType) (s25.PrivateMessageIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	rule() aper.SourceRule
}

func BridgePrivateMessageIEsValueCaptureS1APPrivateIEField(v *s25.PrivateMessageIEsValuePrivateIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s20.BridgeCaptureS1APPrivateIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s25.BridgePrivateMessageIEsValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s25.BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v), *s25.BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v))
}
func BridgePrivateMessageIEsValueCompareS1APPrivateIEField(v *s25.PrivateMessageIEsValuePrivateIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s20.BridgeCompareS1APPrivateIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s25.BridgePrivateMessageIEsValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s25.BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v), *s25.BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v))
}

// recommendedCellsForPagingItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RecommendedCellsForPagingItemExtIEsValue].
type RecommendedCellsForPagingItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.RecommendedCellsForPagingItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.RecommendedCellsForPagingItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.RecommendedCellsForPagingItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeRecommendedCellsForPagingItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldReplay(v), *s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.RecommendedCellsForPagingItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeRecommendedCellsForPagingItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldReplay(v), *s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldWithoutReplay(v))
}

// recommendedCellItemIEValueProtocolOpenValue is the concrete protocolOpenValue[RecommendedCellItemIEValue].
type RecommendedCellItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) RecommendedCellItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (RecommendedCellItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRecommendedCellItemIEValueCaptureS1APProtocolIEField(v *RecommendedCellItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeRecommendedCellItemIEValueCompareS1APProtocolIEField(v *RecommendedCellItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// recommendedCellsForPagingExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RecommendedCellsForPagingExtIEsValue].
type RecommendedCellsForPagingExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.RecommendedCellsForPagingExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.RecommendedCellsForPagingExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionField(v *s11.RecommendedCellsForPagingExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeRecommendedCellsForPagingExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeRecommendedCellsForPagingExtIEsExtFieldFieldReplay(v), *s11.BridgeRecommendedCellsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionField(v *s11.RecommendedCellsForPagingExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeRecommendedCellsForPagingExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeRecommendedCellsForPagingExtIEsExtFieldFieldReplay(v), *s11.BridgeRecommendedCellsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}

// recommendedENBItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RecommendedENBItemExtIEsValue].
type RecommendedENBItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.RecommendedENBItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.RecommendedENBItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRecommendedENBItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.RecommendedENBItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeRecommendedENBItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeRecommendedENBItemExtIEsExtFieldFieldReplay(v), *s11.BridgeRecommendedENBItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRecommendedENBItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.RecommendedENBItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeRecommendedENBItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeRecommendedENBItemExtIEsExtFieldFieldReplay(v), *s11.BridgeRecommendedENBItemExtIEsExtFieldFieldWithoutReplay(v))
}

// recommendedENBsForPagingExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RecommendedENBsForPagingExtIEsValue].
type RecommendedENBsForPagingExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.RecommendedENBsForPagingExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.RecommendedENBsForPagingExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRecommendedENBsForPagingExtIEsValueCaptureS1APProtocolExtensionField(v *s11.RecommendedENBsForPagingExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeRecommendedENBsForPagingExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeRecommendedENBsForPagingExtIEsExtFieldFieldReplay(v), *s11.BridgeRecommendedENBsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRecommendedENBsForPagingExtIEsValueCompareS1APProtocolExtensionField(v *s11.RecommendedENBsForPagingExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeRecommendedENBsForPagingExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeRecommendedENBsForPagingExtIEsExtFieldFieldReplay(v), *s11.BridgeRecommendedENBsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}

// requestTypeExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RequestTypeExtIEsValue].
type RequestTypeExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.RequestTypeExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.RequestTypeExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRequestTypeExtIEsValueCaptureS1APProtocolExtensionField(v *s11.RequestTypeExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeRequestTypeExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeRequestTypeExtIEsExtFieldFieldReplay(v), *s11.BridgeRequestTypeExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRequestTypeExtIEsValueCompareS1APProtocolExtensionField(v *s11.RequestTypeExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeRequestTypeExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeRequestTypeExtIEsExtFieldFieldReplay(v), *s11.BridgeRequestTypeExtIEsExtFieldFieldWithoutReplay(v))
}

// requestedTNLInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RequestedTNLInfoExtIEsValue].
type RequestedTNLInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.RequestedTNLInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.RequestedTNLInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRequestedTNLInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s11.RequestedTNLInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeRequestedTNLInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeRequestedTNLInfoExtIEsExtFieldFieldReplay(v), *s11.BridgeRequestedTNLInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRequestedTNLInfoExtIEsValueCompareS1APProtocolExtensionField(v *s11.RequestedTNLInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeRequestedTNLInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeRequestedTNLInfoExtIEsExtFieldFieldReplay(v), *s11.BridgeRequestedTNLInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRerouteNASRequestIEValueCaptureS1APProtocolIEField(v *s20.RerouteNASRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s20.BridgeRerouteNASRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s20.BridgeRerouteNASRequestIEFieldFieldReplay(v), *s20.BridgeRerouteNASRequestIEFieldFieldWithoutReplay(v))
}
func BridgeRerouteNASRequestIEValueCompareS1APProtocolIEField(v *s20.RerouteNASRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s20.BridgeRerouteNASRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s20.BridgeRerouteNASRequestIEFieldFieldReplay(v), *s20.BridgeRerouteNASRequestIEFieldFieldWithoutReplay(v))
}

// RecommendedCellItemAPERValue is the concrete APERValue[RecommendedCellItem].
type RecommendedCellItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   RecommendedCellItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellItemAPERValue) WithoutReplay() RecommendedCellItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RequestedTNLInfoAPERValue is the concrete APERValue[RequestedTNLInfo].
type RequestedTNLInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   RequestedTNLInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RequestedTNLInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestedTNLInfoAPERValue) WithoutReplay() RequestedTNLInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RequestTypeAPERValue is the concrete APERValue[RequestType].
type RequestTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   RequestType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RequestTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestTypeAPERValue) WithoutReplay() RequestTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceDataForPagingAPERValue is the concrete APERValue[AssistanceDataForPaging].
type AssistanceDataForPagingAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceDataForPaging

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AssistanceDataForPagingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForPagingAPERValue) WithoutReplay() AssistanceDataForPagingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceDataForRecommendedCellsAPERValue is the concrete APERValue[AssistanceDataForRecommendedCells].
type AssistanceDataForRecommendedCellsAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceDataForRecommendedCells

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AssistanceDataForRecommendedCellsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForRecommendedCellsAPERValue) WithoutReplay() AssistanceDataForRecommendedCellsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingControlAPERValue is the concrete APERValue[LocationReportingControl].
type LocationReportingControlAPERValue struct {
	context s00.BridgeCodecContext
	Value   LocationReportingControl

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingControlAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingControlAPERValue) WithoutReplay() LocationReportingControlAPERValue {
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

// PathSwitchRequestFailureAPERValue is the concrete APERValue[PathSwitchRequestFailure].
type PathSwitchRequestFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   PathSwitchRequestFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestFailureAPERValue) WithoutReplay() PathSwitchRequestFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateMessageAPERValue is the concrete APERValue[PrivateMessage].
type PrivateMessageAPERValue struct {
	context s00.BridgeCodecContext
	Value   PrivateMessage

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PrivateMessageAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PrivateMessageAPERValue) WithoutReplay() PrivateMessageAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellListAPERValue is the concrete APERValue[RecommendedCellList].
type RecommendedCellListAPERValue struct {
	context s00.BridgeCodecContext
	Value   RecommendedCellList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellListAPERValue) WithoutReplay() RecommendedCellListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellsForPagingAPERValue is the concrete APERValue[RecommendedCellsForPaging].
type RecommendedCellsForPagingAPERValue struct {
	context s00.BridgeCodecContext
	Value   RecommendedCellsForPaging

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellsForPagingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingAPERValue) WithoutReplay() RecommendedCellsForPagingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingControlIEValueERABIEContainerListValueCodec is the concrete ValueCodec[LocationReportingControlIEValueERABIEContainerList].
type LocationReportingControlIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingControlIEValueERABIEContainerList, error)
	encode  func(LocationReportingControlIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingControlIEValueERABIEContainerList, aper.DecodeState) (LocationReportingControlIEValueERABIEContainerList, aper.Snapshot)
	compare func(LocationReportingControlIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingControlIEValueERABIEContainerListValueCodec) New(value LocationReportingControlIEValueERABIEContainerList) (LocationReportingControlIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportingControlIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingControlIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingControlIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingControlIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingControlIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingControlIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingControlIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingControlIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingControlIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingControlIEValueERABIEContainerListValueCodec) EncodeAPER(value LocationReportingControlIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingControlIEValueERABIEContainerListValueCodec) encodeBudgetValue(value LocationReportingControlIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingControlIEValueERABIEContainerListValueCodec) encodeChanged(value LocationReportingControlIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingControlIEValueERABIEContainerList is E-RAB-IE-ContainerList {{LocationReportingControlIEs}} of TS 36.413: a list of information element fields.
type LocationReportingControlIEValueERABIEContainerList []LocationReportingControlIEValueProtocolIESingleContainer

func BridgeLocationReportingControlIEValueCaptureS1APERABIEContainerList(v *LocationReportingControlIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingControlIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportingControlIEValueCompareS1APERABIEContainerList(v *LocationReportingControlIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingControlIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APERABIEContainerList(v *s23.PathSwitchRequestFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestFailureIEValueCompareS1APERABIEContainerList(v *s23.PathSwitchRequestFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// RecommendedCellItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[RecommendedCellItemIEValueERABIEContainerList].
type RecommendedCellItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellItemIEValueERABIEContainerList, error)
	encode  func(RecommendedCellItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellItemIEValueERABIEContainerList, aper.DecodeState) (RecommendedCellItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(RecommendedCellItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellItemIEValueERABIEContainerListValueCodec) New(value RecommendedCellItemIEValueERABIEContainerList) (RecommendedCellItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellItemIEValueERABIEContainerListValueCodec) EncodeAPER(value RecommendedCellItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedCellItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value RecommendedCellItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellItemIEValueERABIEContainerListValueCodec) encodeChanged(value RecommendedCellItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{RecommendedCellItemIEs}} of TS 36.413: a list of information element fields.
type RecommendedCellItemIEValueERABIEContainerList []RecommendedCellItemIEValueProtocolIESingleContainer

func BridgeRecommendedCellItemIEValueCaptureS1APERABIEContainerList(v *RecommendedCellItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedCellItemIEValueCompareS1APERABIEContainerList(v *RecommendedCellItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRerouteNASRequestIEValueCaptureS1APERABIEContainerList(v *s20.RerouteNASRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRerouteNASRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// LocationReportingControlIEFieldValueCodec is the concrete ValueCodec[LocationReportingControlIEField].
type LocationReportingControlIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingControlIEField, error)
	encode  func(LocationReportingControlIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingControlIEField, aper.DecodeState) (LocationReportingControlIEField, aper.Snapshot)
	compare func(LocationReportingControlIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingControlIEFieldValueCodec) New(value LocationReportingControlIEField) (LocationReportingControlIEFieldAPERValue, error) {
	if c.encode == nil {
		return LocationReportingControlIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingControlIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingControlIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingControlIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingControlIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingControlIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingControlIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingControlIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingControlIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingControlIEFieldValueCodec) EncodeAPER(value LocationReportingControlIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingControlIEFieldValueCodec) encodeBudgetValue(value LocationReportingControlIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingControlIEFieldValueCodec) encodeChanged(value LocationReportingControlIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellItemIEFieldValueCodec is the concrete ValueCodec[RecommendedCellItemIEField].
type RecommendedCellItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellItemIEField, error)
	encode  func(RecommendedCellItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellItemIEField, aper.DecodeState) (RecommendedCellItemIEField, aper.Snapshot)
	compare func(RecommendedCellItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellItemIEFieldValueCodec) New(value RecommendedCellItemIEField) (RecommendedCellItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellItemIEFieldValueCodec) EncodeAPER(value RecommendedCellItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedCellItemIEFieldValueCodec) encodeBudgetValue(value RecommendedCellItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellItemIEFieldValueCodec) encodeChanged(value RecommendedCellItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingControlIEContainerValueCodec is the concrete ValueCodec[LocationReportingControlIEContainer].
type LocationReportingControlIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingControlIEContainer, error)
	encode  func(LocationReportingControlIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingControlIEContainer, aper.DecodeState) (LocationReportingControlIEContainer, aper.Snapshot)
	compare func(LocationReportingControlIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingControlIEContainerValueCodec) New(value LocationReportingControlIEContainer) (LocationReportingControlIEContainerAPERValue, error) {
	if c.encode == nil {
		return LocationReportingControlIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingControlIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingControlIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingControlIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingControlIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingControlIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingControlIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingControlIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingControlIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingControlIEContainerValueCodec) EncodeAPER(value LocationReportingControlIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingControlIEContainerValueCodec) encodeBudgetValue(value LocationReportingControlIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingControlIEContainerValueCodec) encodeChanged(value LocationReportingControlIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellItemIEContainerValueCodec is the concrete ValueCodec[RecommendedCellItemIEContainer].
type RecommendedCellItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellItemIEContainer, error)
	encode  func(RecommendedCellItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellItemIEContainer, aper.DecodeState) (RecommendedCellItemIEContainer, aper.Snapshot)
	compare func(RecommendedCellItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellItemIEContainerValueCodec) New(value RecommendedCellItemIEContainer) (RecommendedCellItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellItemIEContainerValueCodec) EncodeAPER(value RecommendedCellItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedCellItemIEContainerValueCodec) encodeBudgetValue(value RecommendedCellItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellItemIEContainerValueCodec) encodeChanged(value RecommendedCellItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeRecommendedCellItemIEValueCaptureS1APProtocolIEContainer(v *RecommendedCellItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedCellItemIEValueCompareS1APProtocolIEContainer(v *RecommendedCellItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[LocationReportingControlIEValueProtocolErrorIEContainerList].
type LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingControlIEValueProtocolErrorIEContainerList, error)
	encode  func(LocationReportingControlIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingControlIEValueProtocolErrorIEContainerList, aper.DecodeState) (LocationReportingControlIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(LocationReportingControlIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) New(value LocationReportingControlIEValueProtocolErrorIEContainerList) (LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value LocationReportingControlIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value LocationReportingControlIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingControlIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{LocationReportingControlIEs}} of TS 36.413: a list of information element fields.
type LocationReportingControlIEValueProtocolErrorIEContainerList []LocationReportingControlIEValueProtocolIESingleContainer

func BridgeLocationReportingControlIEValueCaptureS1APProtocolErrorIEContainerList(v *LocationReportingControlIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingControlIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportingControlIEValueCompareS1APProtocolErrorIEContainerList(v *LocationReportingControlIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingControlIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s23.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[RecommendedCellItemIEValueProtocolErrorIEContainerList].
type RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellItemIEValueProtocolErrorIEContainerList, error)
	encode  func(RecommendedCellItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (RecommendedCellItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(RecommendedCellItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) New(value RecommendedCellItemIEValueProtocolErrorIEContainerList) (RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value RecommendedCellItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value RecommendedCellItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{RecommendedCellItemIEs}} of TS 36.413: a list of information element fields.
type RecommendedCellItemIEValueProtocolErrorIEContainerList []RecommendedCellItemIEValueProtocolIESingleContainer

func BridgeRecommendedCellItemIEValueCaptureS1APProtocolErrorIEContainerList(v *RecommendedCellItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedCellItemIEValueCompareS1APProtocolErrorIEContainerList(v *RecommendedCellItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRerouteNASRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s20.RerouteNASRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRerouteNASRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// LocationReportingControlIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[LocationReportingControlIEValueProtocolIEContainerList].
type LocationReportingControlIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingControlIEValueProtocolIEContainerList, error)
	encode  func(LocationReportingControlIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingControlIEValueProtocolIEContainerList, aper.DecodeState) (LocationReportingControlIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(LocationReportingControlIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingControlIEValueProtocolIEContainerListValueCodec) New(value LocationReportingControlIEValueProtocolIEContainerList) (LocationReportingControlIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportingControlIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingControlIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingControlIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingControlIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingControlIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingControlIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingControlIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingControlIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingControlIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingControlIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingControlIEValueProtocolIEContainerListValueCodec) EncodeAPER(value LocationReportingControlIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingControlIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value LocationReportingControlIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingControlIEValueProtocolIEContainerListValueCodec) encodeChanged(value LocationReportingControlIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingControlIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {LocationReportingControlIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type LocationReportingControlIEValueProtocolIEContainerList []LocationReportingControlIEValueProtocolIESingleContainer

func BridgeLocationReportingControlIEValueCaptureS1APProtocolIEContainerList(v *LocationReportingControlIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingControlIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportingControlIEValueCompareS1APProtocolIEContainerList(v *LocationReportingControlIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportingControlIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainerList(v *s23.PathSwitchRequestFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainerList(v *s23.PathSwitchRequestFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// RecommendedCellItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[RecommendedCellItemIEValueProtocolIEContainerList].
type RecommendedCellItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellItemIEValueProtocolIEContainerList, error)
	encode  func(RecommendedCellItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellItemIEValueProtocolIEContainerList, aper.DecodeState) (RecommendedCellItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(RecommendedCellItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellItemIEValueProtocolIEContainerListValueCodec) New(value RecommendedCellItemIEValueProtocolIEContainerList) (RecommendedCellItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value RecommendedCellItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedCellItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value RecommendedCellItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value RecommendedCellItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {RecommendedCellItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type RecommendedCellItemIEValueProtocolIEContainerList []RecommendedCellItemIEValueProtocolIESingleContainer

func BridgeRecommendedCellItemIEValueCaptureS1APProtocolIEContainerList(v *RecommendedCellItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedCellItemIEValueCompareS1APProtocolIEContainerList(v *RecommendedCellItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRerouteNASRequestIEValueCaptureS1APProtocolIEContainerList(v *s20.RerouteNASRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRerouteNASRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// LocationReportingControlIEValueERABIEContainerListAPERValue is the concrete APERValue[LocationReportingControlIEValueERABIEContainerList].
type LocationReportingControlIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingControlIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingControlIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingControlIEValueERABIEContainerListAPERValue) WithoutReplay() LocationReportingControlIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingControlIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{LocationReportingControlIEs}} of TS 36.413: a single information element field.
type LocationReportingControlIEValueProtocolIESingleContainer = LocationReportingControlIEField

func BridgeLocationReportingControlIEValueCaptureS1APProtocolIESingleContainer(v *LocationReportingControlIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingControlIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeLocationReportingControlIEValueCompareS1APProtocolIESingleContainer(v *LocationReportingControlIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingControlIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(v *s23.MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v, s)
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIESingleContainer(v *s23.PathSwitchRequestFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIESingleContainer(v *s23.PathSwitchRequestFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// RecommendedCellItemIEValueERABIEContainerListAPERValue is the concrete APERValue[RecommendedCellItemIEValueERABIEContainerList].
type RecommendedCellItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellItemIEValueERABIEContainerListAPERValue) WithoutReplay() RecommendedCellItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeRerouteNASRequestIEValueCaptureS1APProtocolIESingleContainer(v *s20.RerouteNASRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRerouteNASRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}

// LocationReportingControlIEFieldAPERValue is the concrete APERValue[LocationReportingControlIEField].
type LocationReportingControlIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingControlIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingControlIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingControlIEFieldAPERValue) WithoutReplay() LocationReportingControlIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellItemIEFieldAPERValue is the concrete APERValue[RecommendedCellItemIEField].
type RecommendedCellItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellItemIEFieldAPERValue) WithoutReplay() RecommendedCellItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingControlIEContainerAPERValue is the concrete APERValue[LocationReportingControlIEContainer].
type LocationReportingControlIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingControlIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingControlIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingControlIEContainerAPERValue) WithoutReplay() LocationReportingControlIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellItemIEContainerAPERValue is the concrete APERValue[RecommendedCellItemIEContainer].
type RecommendedCellItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellItemIEContainerAPERValue) WithoutReplay() RecommendedCellItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[LocationReportingControlIEValueProtocolErrorIEContainerList].
type LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingControlIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[RecommendedCellItemIEValueProtocolErrorIEContainerList].
type RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingControlIEValueProtocolIEContainerListAPERValue is the concrete APERValue[LocationReportingControlIEValueProtocolIEContainerList].
type LocationReportingControlIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingControlIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingControlIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingControlIEValueProtocolIEContainerListAPERValue) WithoutReplay() LocationReportingControlIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[RecommendedCellItemIEValueProtocolIEContainerList].
type RecommendedCellItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() RecommendedCellItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APAssistanceDataForPaging(v *AssistanceDataForPaging, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.AssistanceDataForRecommendedCells == nil)
		if v.AssistanceDataForRecommendedCells != nil {
			BridgeCaptureS1APAssistanceDataForRecommendedCells(v.AssistanceDataForRecommendedCells, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.AssistanceDataForCECapableUEs == nil)
		if v.AssistanceDataForCECapableUEs != nil {
			s17.BridgeCaptureS1APAssistanceDataForCECapableUEs(v.AssistanceDataForCECapableUEs, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PagingAttemptInformation == nil)
		if v.PagingAttemptInformation != nil {
			s20.BridgeCaptureS1APPagingAttemptInformation(v.PagingAttemptInformation, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s12.BridgeAssistanceDataForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APAssistanceDataForPaging(v *AssistanceDataForPaging, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.AssistanceDataForRecommendedCells == nil)
		if v.AssistanceDataForRecommendedCells != nil {
			BridgeCompareS1APAssistanceDataForRecommendedCells(v.AssistanceDataForRecommendedCells, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.AssistanceDataForCECapableUEs == nil)
		if v.AssistanceDataForCECapableUEs != nil {
			s17.BridgeCompareS1APAssistanceDataForCECapableUEs(v.AssistanceDataForCECapableUEs, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PagingAttemptInformation == nil)
		if v.PagingAttemptInformation != nil {
			s20.BridgeCompareS1APPagingAttemptInformation(v.PagingAttemptInformation, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s12.BridgeAssistanceDataForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APAssistanceDataForRecommendedCells(v *AssistanceDataForRecommendedCells, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APRecommendedCellsForPaging(&v.RecommendedCellsForPaging, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeAssistanceDataForRecommendedCellsExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APAssistanceDataForRecommendedCells(v *AssistanceDataForRecommendedCells, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APRecommendedCellsForPaging(&v.RecommendedCellsForPaging, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeAssistanceDataForRecommendedCellsExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLocationReportingControl(v *LocationReportingControl, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingControlIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLocationReportingControl(v *LocationReportingControl, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingControlIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLocationReportingControlIEValue(v *LocationReportingControlIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(98):
			{
				f := s.Begin()
				s.Bool(v.rowRequestType == nil)
				if v.rowRequestType != nil {
					BridgeCaptureS1APRequestType(v.rowRequestType, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v LocationReportingControlIEValue) captureSemantics(s aper.SemanticCapture) LocationReportingControlIEValue {
	BridgeCaptureS1APLocationReportingControlIEValue(&v, &s)
	return v
}
func BridgeCompareS1APLocationReportingControlIEValue(v *LocationReportingControlIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(98):
			{
				f := s.Begin()
				s.Bool(v.rowRequestType == nil)
				if v.rowRequestType != nil {
					BridgeCompareS1APRequestType(v.rowRequestType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v LocationReportingControlIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APLocationReportingControlIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMMEConfigurationUpdateFailure(v *MMEConfigurationUpdateFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEConfigurationUpdateFailure(v *MMEConfigurationUpdateFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
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
func BridgeCaptureS1APPathSwitchRequestFailure(v *PathSwitchRequestFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPathSwitchRequestFailure(v *PathSwitchRequestFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPrivateMessage(v *PrivateMessage, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePrivateMessageIEsValueCaptureS1APPrivateIEContainer(&v.PrivateIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPrivateMessage(v *PrivateMessage, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePrivateMessageIEsValueCompareS1APPrivateIEContainer(&v.PrivateIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRecommendedCellItem(v *RecommendedCellItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s17.BridgeCaptureS1APEUTRANCGI(&v.EUTRANCGI, s)
	{
		f := s.Begin()
		s.Bool(v.TimeStayedInCell == nil)
		if v.TimeStayedInCell != nil {
			s.Int(int64((*v.TimeStayedInCell)))
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRecommendedCellItem(v *RecommendedCellItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s17.BridgeCompareS1APEUTRANCGI(&v.EUTRANCGI, s)
	{
		f := s.Begin()
		s.Bool(v.TimeStayedInCell == nil)
		if v.TimeStayedInCell != nil {
			s.Int(int64((*v.TimeStayedInCell)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRecommendedCellItemIEValue(v *RecommendedCellItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(214):
			{
				f := s.Begin()
				s.Bool(v.rowRecommendedCellItem == nil)
				if v.rowRecommendedCellItem != nil {
					BridgeCaptureS1APRecommendedCellItem(v.rowRecommendedCellItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v RecommendedCellItemIEValue) captureSemantics(s aper.SemanticCapture) RecommendedCellItemIEValue {
	BridgeCaptureS1APRecommendedCellItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APRecommendedCellItemIEValue(v *RecommendedCellItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(214):
			{
				f := s.Begin()
				s.Bool(v.rowRecommendedCellItem == nil)
				if v.rowRecommendedCellItem != nil {
					BridgeCompareS1APRecommendedCellItem(v.rowRecommendedCellItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v RecommendedCellItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APRecommendedCellItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APRecommendedCellList(v *RecommendedCellList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APRecommendedCellList(v *RecommendedCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedCellItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APRecommendedCellsForPaging(v *RecommendedCellsForPaging, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APRecommendedCellList(&v.RecommendedCellList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRecommendedCellsForPaging(v *RecommendedCellsForPaging, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APRecommendedCellList(&v.RecommendedCellList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRequestType(v *RequestType, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEventType(&v.EventType, s)
	s00.BridgeCaptureS1APReportArea(&v.ReportArea, s)
	s.Bool(v.IEExtensions == nil)
	BridgeRequestTypeExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRequestType(v *RequestType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEventType(&v.EventType, s)
	s06.BridgeCompareS1APReportArea(&v.ReportArea, s)
	s.Bool(v.IEExtensions == nil)
	BridgeRequestTypeExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRequestedTNLInfo(v *RequestedTNLInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s.Bool(v.IEExtensions == nil)
	BridgeRequestedTNLInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRequestedTNLInfo(v *RequestedTNLInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s.Bool(v.IEExtensions == nil)
	BridgeRequestedTNLInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// NewPrivateIEIDLocal creates a PrivateIEID with the local alternative.
func BridgeNewPrivateIEIDLocalLegacy(v int64) s20.PrivateIEID {
	return s20.PrivateIEID{
		Choice: s00.PrivateIEIDChoiceLocal,
		Local:  &v,
	}
}

// NewPrivateIEIDGlobal creates a PrivateIEID with the global alternative.
func BridgeNewPrivateIEIDGlobalLegacy(v runtime.ObjectIdentifier) s20.PrivateIEID {
	return s20.PrivateIEID{
		Choice: s00.PrivateIEIDChoiceGlobal,
		Global: &v,
	}
}

// NewPrivateIEIDLocal constructs a checked complete value.
func NewPrivateIEIDLocal(v int64, options ...aper.BuildOption) (s20.PrivateIEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDLocal")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDLocal")
	}
	value := BridgeNewPrivateIEIDLocalLegacy(v)
	if _, err := s20.BridgePrivateIEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDLocal")
	}
	return value, aper.OperationError(nil, "PrivateIEIDLocal")
}

// NewPrivateIEIDGlobal constructs a checked complete value.
func NewPrivateIEIDGlobal(v runtime.ObjectIdentifier, options ...aper.BuildOption) (s20.PrivateIEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDGlobal")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDGlobal")
	}
	value := BridgeNewPrivateIEIDGlobalLegacy(v)
	if _, err := s20.BridgePrivateIEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDGlobal")
	}
	return value, aper.OperationError(nil, "PrivateIEIDGlobal")
}

// AssistanceDataForPaging represents the ASN.1 type AssistanceDataForPaging (SEQUENCE).
type AssistanceDataForPaging struct {
	replay                            aper.Snapshot
	stream                            aper.WireSpan
	received                          bool
	withoutReplay                     bool
	receivedAbsolute                  bool
	receivedBytes                     aper.WireSpan
	receivedLocation                  aper.Location
	AssistanceDataForRecommendedCells *AssistanceDataForRecommendedCells            `asn1:"tag:0,context,implicit,optional" json:"AssistanceDataForRecommendedCells,omitempty"`
	AssistanceDataForCECapableUEs     *s17.AssistanceDataForCECapableUEs            `asn1:"tag:1,context,implicit,optional" json:"AssistanceDataForCECapableUEs,omitempty"`
	PagingAttemptInformation          *s20.PagingAttemptInformation                 `asn1:"tag:2,context,implicit,optional" json:"PagingAttemptInformation,omitempty"`
	IEExtensions                      s07.AssistanceDataForPagingExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                 bool                                          `asn1:"-" json:"-"`
	extCount                          int64                                         `asn1:"-" json:"-"`
	extPresent                        []bool                                        `asn1:"-" json:"-"`
	extData                           [][]byte                                      `asn1:"-" json:"-"`
	perPadding                        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding                     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin                         []aper.OpaqueOrigin
	extWire                           []aper.WireSpan
}

// AssistanceDataForRecommendedCells represents the ASN.1 type AssistanceDataForRecommendedCells (SEQUENCE).
type AssistanceDataForRecommendedCells struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	RecommendedCellsForPaging RecommendedCellsForPaging                               `asn1:"tag:0,context,implicit"`
	IEExtensions              s07.AssistanceDataForRecommendedCellsExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                                    `asn1:"-" json:"-"`
	extCount                  int64                                                   `asn1:"-" json:"-"`
	extPresent                []bool                                                  `asn1:"-" json:"-"`
	extData                   [][]byte                                                `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                                       `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                                  `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
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
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12Legacy(v s14.COUNTvalue) s15.DLCOUNTPDCPSNlength {
	return s15.DLCOUNTPDCPSNlength{
		Choice:                     s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12,
		DLCOUNTValuePDCPSNlength12: &v,
	}
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15 creates a DLCOUNTPDCPSNlength with the dLCOUNTValuePDCP-SNlength15 alternative.
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15Legacy(v s14.COUNTValueExtended) s15.DLCOUNTPDCPSNlength {
	return s15.DLCOUNTPDCPSNlength{
		Choice:                     s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15,
		DLCOUNTValuePDCPSNlength15: &v,
	}
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18 creates a DLCOUNTPDCPSNlength with the dLCOUNTValuePDCP-SNlength18 alternative.
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18Legacy(v s14.COUNTvaluePDCPSNlength18) s15.DLCOUNTPDCPSNlength {
	return s15.DLCOUNTPDCPSNlength{
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

// NewLastVisitedGERANCellInformationUndefined creates a LastVisitedGERANCellInformation with the undefined alternative.
func BridgeNewLastVisitedGERANCellInformationUndefinedLegacy(v struct{}) s18.LastVisitedGERANCellInformation {
	return s18.LastVisitedGERANCellInformation{
		Choice:    s00.LastVisitedGERANCellInformationChoiceUndefined,
		Undefined: &v,
	}
}

// NewLoggedMDTTriggerPeriodical creates a LoggedMDTTrigger with the periodical alternative.
func BridgeNewLoggedMDTTriggerPeriodicalLegacy(v struct{}) s19.LoggedMDTTrigger {
	return s19.LoggedMDTTrigger{
		Choice:     s00.LoggedMDTTriggerChoicePeriodical,
		Periodical: &v,
	}
}

// NewLoggedMDTTriggerEventTrigger creates a LoggedMDTTrigger with the eventTrigger alternative.
func BridgeNewLoggedMDTTriggerEventTriggerLegacy(v s19.EventTrigger) s19.LoggedMDTTrigger {
	return s19.LoggedMDTTrigger{
		Choice:       s00.LoggedMDTTriggerChoiceEventTrigger,
		EventTrigger: &v,
	}
}

// NewMeasurementThresholdA2ThresholdRSRP creates a MeasurementThresholdA2 with the threshold-RSRP alternative.
func BridgeNewMeasurementThresholdA2ThresholdRSRPLegacy(v s00.ThresholdRSRP) s19.MeasurementThresholdA2 {
	return s19.MeasurementThresholdA2{
		Choice:        s00.MeasurementThresholdA2ChoiceThresholdRSRP,
		ThresholdRSRP: &v,
	}
}

// NewMeasurementThresholdA2ThresholdRSRQ creates a MeasurementThresholdA2 with the threshold-RSRQ alternative.
func BridgeNewMeasurementThresholdA2ThresholdRSRQLegacy(v s00.ThresholdRSRQ) s19.MeasurementThresholdA2 {
	return s19.MeasurementThresholdA2{
		Choice:        s00.MeasurementThresholdA2ChoiceThresholdRSRQ,
		ThresholdRSRQ: &v,
	}
}

// NewMeasurementThresholdL1LoggedMDTThresholdRSRP creates a MeasurementThresholdL1LoggedMDT with the threshold-RSRP alternative.
func BridgeNewMeasurementThresholdL1LoggedMDTThresholdRSRPLegacy(v s00.ThresholdRSRP) s19.MeasurementThresholdL1LoggedMDT {
	return s19.MeasurementThresholdL1LoggedMDT{
		Choice:        s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRP,
		ThresholdRSRP: &v,
	}
}

// NewMeasurementThresholdL1LoggedMDTThresholdRSRQ creates a MeasurementThresholdL1LoggedMDT with the threshold-RSRQ alternative.
func BridgeNewMeasurementThresholdL1LoggedMDTThresholdRSRQLegacy(v s00.ThresholdRSRQ) s19.MeasurementThresholdL1LoggedMDT {
	return s19.MeasurementThresholdL1LoggedMDT{
		Choice:        s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ,
		ThresholdRSRQ: &v,
	}
}

// NewMeasurementThresholdL1LoggedMDTChoiceExtensions creates a MeasurementThresholdL1LoggedMDT with the choice-Extensions alternative.
func BridgeNewMeasurementThresholdL1LoggedMDTChoiceExtensionsLegacy(v s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer) s19.MeasurementThresholdL1LoggedMDT {
	return s19.MeasurementThresholdL1LoggedMDT{
		Choice:           s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions,
		ChoiceExtensions: &v,
	}
}

// NewOverloadResponseOverloadAction creates a OverloadResponse with the overloadAction alternative.
func BridgeNewOverloadResponseOverloadActionLegacy(v s00.OverloadAction) s20.OverloadResponse {
	return s20.OverloadResponse{
		Choice:         s00.OverloadResponseChoiceOverloadAction,
		OverloadAction: &v,
	}
}

// RecommendedCellsForPaging represents the ASN.1 type RecommendedCellsForPaging (SEQUENCE).
type RecommendedCellsForPaging struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	RecommendedCellList      RecommendedCellList                             `asn1:"tag:0,context,implicit"`
	recommendedCellListIndef bool                                            `asn1:"-" json:"-"`
	IEExtensions             s11.RecommendedCellsForPagingExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                            `asn1:"-" json:"-"`
	extCount                 int64                                           `asn1:"-" json:"-"`
	extPresent               []bool                                          `asn1:"-" json:"-"`
	extData                  [][]byte                                        `asn1:"-" json:"-"`
	perPadding               aper.FinalPadding                               `asn1:"-" json:"-"`
	perExtPadding            []aper.CompletePadding                          `asn1:"-" json:"-"`
	extOrigin                []aper.OpaqueOrigin
	extWire                  []aper.WireSpan
}
type RecommendedCellList = []RecommendedCellItemIEValueProtocolIESingleContainer

// RecommendedCellItem represents the ASN.1 type RecommendedCellItem (SEQUENCE).
type RecommendedCellItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	EUTRANCGI         s17.EUTRANCGI                                       `asn1:"tag:0,context,implicit"`
	TimeStayedInCell  *int64                                              `asn1:"tag:1,context,implicit,optional" json:"TimeStayedInCell,omitempty"`
	IEExtensions      s11.RecommendedCellsForPagingItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                `asn1:"-" json:"-"`
	extCount          int64                                               `asn1:"-" json:"-"`
	extPresent        []bool                                              `asn1:"-" json:"-"`
	extData           [][]byte                                            `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                   `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                              `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// RequestedTNLInfo represents the ASN.1 type RequestedTNLInfo (SEQUENCE).
type RequestedTNLInfo struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity                       `asn1:"tag:0,context,implicit"`
	IEExtensions      s11.RequestedTNLInfoExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                   `asn1:"-" json:"-"`
	extCount          int64                                  `asn1:"-" json:"-"`
	extPresent        []bool                                 `asn1:"-" json:"-"`
	extData           [][]byte                               `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// RequestType represents the ASN.1 type RequestType (SEQUENCE).
type RequestType struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	EventType         s00.EventType                     `asn1:"tag:0,context,implicit"`
	ReportArea        s00.ReportArea                    `asn1:"tag:1,context,implicit"`
	IEExtensions      s11.RequestTypeExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// NewSONInformationReportRLFReportInformation creates a SONInformationReport with the rLFReportInformation alternative.
func BridgeNewSONInformationReportRLFReportInformationLegacy(v s20.RLFReportInformation) s20.SONInformationReport {
	return s20.SONInformationReport{
		Choice:               s00.SONInformationReportChoiceRLFReportInformation,
		RLFReportInformation: &v,
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

// MarshalAPER encodes AssistanceDataForPaging to APER format.
func (v *AssistanceDataForPaging) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceDataForPaging) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.AssistanceDataForRecommendedCells != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.AssistanceDataForCECapableUEs != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.PagingAttemptInformation != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.AssistanceDataForRecommendedCells != nil {
		if err := v.AssistanceDataForRecommendedCells.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding assistanceDataForRecommendedCells: %w", err)
		}
	}
	if v.AssistanceDataForCECapableUEs != nil {
		if err := s17.BridgeAssistanceDataForCECapableUEsMethodMarshalAPERTo(v.AssistanceDataForCECapableUEs, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding assistanceDataForCECapableUEs: %w", err)
		}
	}
	if v.PagingAttemptInformation != nil {
		if err := s20.BridgePagingAttemptInformationMethodMarshalAPERTo(v.PagingAttemptInformation, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding pagingAttemptInformation: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeAssistanceDataForPagingExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceDataForPaging from APER format.
func (v *AssistanceDataForPaging) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceDataForPaging with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceDataForPaging) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForPaging")
	}
	bb.EnterComponent("AssistanceDataForPaging")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForPaging")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceDataForPaging")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForPaging")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceDataForPaging) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceDataForPaging{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_assistancedataforrecommendedcells, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_assistancedataforcecapableues, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_pagingattemptinformation, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_assistancedataforrecommendedcells {
		toleranceMark_assistancedataforrecommendedcells := bb.EnterComponent("AssistanceDataForRecommendedCells")
		var dec_assistancedataforrecommendedcells AssistanceDataForRecommendedCells
		if err := dec_assistancedataforrecommendedcells.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AssistanceDataForRecommendedCells")
		}
		if err := aper.ChargeValue(bb, dec_assistancedataforrecommendedcells); err != nil {
			return err
		}
		v.AssistanceDataForRecommendedCells = &dec_assistancedataforrecommendedcells
		bb.LeaveComponent(toleranceMark_assistancedataforrecommendedcells)
	}
	if opt_assistancedataforcecapableues {
		toleranceMark_assistancedataforcecapableues := bb.EnterComponent("AssistanceDataForCECapableUEs")
		var dec_assistancedataforcecapableues s17.AssistanceDataForCECapableUEs
		if err := s17.BridgeAssistanceDataForCECapableUEsMethodUnmarshalAPERFrom(&dec_assistancedataforcecapableues, bb); err != nil {
			return runtime.WrapDecodePath(err, "AssistanceDataForCECapableUEs")
		}
		if err := aper.ChargeValue(bb, dec_assistancedataforcecapableues); err != nil {
			return err
		}
		v.AssistanceDataForCECapableUEs = &dec_assistancedataforcecapableues
		bb.LeaveComponent(toleranceMark_assistancedataforcecapableues)
	}
	if opt_pagingattemptinformation {
		toleranceMark_pagingattemptinformation := bb.EnterComponent("PagingAttemptInformation")
		var dec_pagingattemptinformation s20.PagingAttemptInformation
		if err := s20.BridgePagingAttemptInformationMethodUnmarshalAPERFrom(&dec_pagingattemptinformation, bb); err != nil {
			return runtime.WrapDecodePath(err, "PagingAttemptInformation")
		}
		if err := aper.ChargeValue(bb, dec_pagingattemptinformation); err != nil {
			return err
		}
		v.PagingAttemptInformation = &dec_pagingattemptinformation
		bb.LeaveComponent(toleranceMark_pagingattemptinformation)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.AssistanceDataForPagingExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.AssistanceDataForPagingExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeAssistanceDataForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes AssistanceDataForRecommendedCells to APER format.
func (v *AssistanceDataForRecommendedCells) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceDataForRecommendedCells) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.RecommendedCellsForPaging.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding recommendedCellsForPaging: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceDataForRecommendedCells from APER format.
func (v *AssistanceDataForRecommendedCells) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceDataForRecommendedCells with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceDataForRecommendedCells) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForRecommendedCells")
	}
	bb.EnterComponent("AssistanceDataForRecommendedCells")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForRecommendedCells")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceDataForRecommendedCells")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForRecommendedCells")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceDataForRecommendedCells) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceDataForRecommendedCells{}
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
	toleranceMark_recommendedcellsforpaging := bb.EnterComponent("RecommendedCellsForPaging")
	if err := v.RecommendedCellsForPaging.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellsForPaging")
	}
	bb.LeaveComponent(toleranceMark_recommendedcellsforpaging)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.AssistanceDataForRecommendedCellsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.AssistanceDataForRecommendedCellsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func BridgeMarshalAPERDAPSResponseInfoListTo(list s15.DAPSResponseInfoList, bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s15.BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// MarshalAPER encodes RecommendedCellsForPaging to APER format.
func (v *RecommendedCellsForPaging) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RecommendedCellsForPaging) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.RecommendedCellList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_recommendedcelllist, fragmentLength_recommendedcelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_recommendedcelllist < 0 || fragmentOffset_recommendedcelllist > int64(len(v.RecommendedCellList)) || fragmentLength_recommendedcelllist < 0 || fragmentLength_recommendedcelllist > int64(len(v.RecommendedCellList[fragmentOffset_recommendedcelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.RecommendedCellList[fragmentOffset_recommendedcelllist : fragmentOffset_recommendedcelllist+fragmentLength_recommendedcelllist] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding recommendedCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding recommendedCellList: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RecommendedCellsForPaging from APER format.
func (v *RecommendedCellsForPaging) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RecommendedCellsForPaging with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RecommendedCellsForPaging) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellsForPaging")
	}
	bb.EnterComponent("RecommendedCellsForPaging")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellsForPaging")
	}
	padding, err := aper.CaptureFinalBits(bb, "RecommendedCellsForPaging")
	if err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellsForPaging")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RecommendedCellsForPaging) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellsForPaging{}
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
	toleranceMark_recommendedcelllist := bb.EnterComponent("RecommendedCellList")
	v.RecommendedCellList = make(RecommendedCellList, 0)
	_, errCollection_recommendedcelllist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_recommendedcelllist, fragmentLength_recommendedcelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_recommendedcelllist < 0 || fragmentLength_recommendedcelllist < 0 || fragmentLength_recommendedcelllist > int64(^uint(0)>>1) || fragmentOffset_recommendedcelllist > int64(^uint(0)>>1)-fragmentLength_recommendedcelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_recommendedcelllist; i++ {
			var elem RecommendedCellItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_recommendedcelllist + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedCellList[%d]", fragmentOffset_recommendedcelllist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.RecommendedCellList, elem); err != nil {
				return err
			} else {
				v.RecommendedCellList = next
			}
		}
		return nil
	})
	if errCollection_recommendedcelllist != nil {
		return runtime.WrapDecodePath(errCollection_recommendedcelllist, "RecommendedCellList")
	}
	bb.LeaveComponent(toleranceMark_recommendedcelllist)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.RecommendedCellsForPagingExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.RecommendedCellsForPagingExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERRecommendedCellListListValue struct{ Value RecommendedCellList }

// MarshalAPERRecommendedCellListTo appends a RecommendedCellList list to bb.
func BridgeMarshalAPERRecommendedCellListTo(list RecommendedCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERRecommendedCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes RecommendedCellItem to APER format.
func (v *RecommendedCellItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RecommendedCellItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.TimeStayedInCell != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&v.EUTRANCGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eUTRAN-CGI: %w", err)
	}
	if v.TimeStayedInCell != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.TimeStayedInCell), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false); err != nil {
			return fmt.Errorf("encoding timeStayedInCell: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RecommendedCellItem from APER format.
func (v *RecommendedCellItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RecommendedCellItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RecommendedCellItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellItem")
	}
	bb.EnterComponent("RecommendedCellItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "RecommendedCellItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RecommendedCellItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_timestayedincell, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_eutrancgi := bb.EnterComponent("EUTRANCGI")
	if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&v.EUTRANCGI, bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANCGI")
	}
	bb.LeaveComponent(toleranceMark_eutrancgi)
	if opt_timestayedincell {
		val_timestayedincell, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "TimeStayedInCell")
		}
		if err := aper.ChargeValue(bb, val_timestayedincell); err != nil {
			return err
		}
		v.TimeStayedInCell = (*int64)(bb.OwnInt64(int64(val_timestayedincell)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.RecommendedCellsForPagingItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.RecommendedCellsForPagingItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes RequestedTNLInfo to APER format.
func (v *RequestedTNLInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RequestedTNLInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeRequestedTNLInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RequestedTNLInfo from APER format.
func (v *RequestedTNLInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RequestedTNLInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RequestedTNLInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RequestedTNLInfo")
	}
	bb.EnterComponent("RequestedTNLInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RequestedTNLInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "RequestedTNLInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "RequestedTNLInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RequestedTNLInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RequestedTNLInfo{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.RequestedTNLInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.RequestedTNLInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeRequestedTNLInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes RequestType to APER format.
func (v *RequestType) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RequestType) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.EventType), 3, true); err != nil {
		return fmt.Errorf("encoding eventType: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.ReportArea), 1, true); err != nil {
		return fmt.Errorf("encoding reportArea: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeRequestTypeExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RequestType from APER format.
func (v *RequestType) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RequestType with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RequestType) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RequestType")
	}
	bb.EnterComponent("RequestType")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RequestType")
	}
	padding, err := aper.CaptureFinalBits(bb, "RequestType")
	if err != nil {
		return runtime.WrapDecodePath(err, "RequestType")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RequestType) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RequestType{}
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
	val_eventtype, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EventType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "EventType")
	}
	v.EventType = s00.EventType(val_eventtype)
	val_reportarea, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "ReportArea"})
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportArea")
	}
	v.ReportArea = s00.ReportArea(val_reportarea)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.RequestTypeExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.RequestTypeExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeRequestTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceDataForPaging) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceDataForPaging", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AssistanceDataForPaging", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceDataForPaging) WithoutReplay() AssistanceDataForPaging {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AssistanceDataForPaging
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceDataForRecommendedCells) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceDataForRecommendedCells", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AssistanceDataForRecommendedCells", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceDataForRecommendedCells) WithoutReplay() AssistanceDataForRecommendedCells {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AssistanceDataForRecommendedCells
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RecommendedCellItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RecommendedCellItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RecommendedCellItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RecommendedCellItem) WithoutReplay() RecommendedCellItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RecommendedCellItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RecommendedCellsForPaging) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RecommendedCellsForPaging", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RecommendedCellsForPaging", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RecommendedCellsForPaging) WithoutReplay() RecommendedCellsForPaging {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RecommendedCellsForPaging
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RequestType) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RequestType", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RequestType", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RequestType) WithoutReplay() RequestType {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RequestType
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RequestedTNLInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RequestedTNLInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RequestedTNLInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RequestedTNLInfo) WithoutReplay() RequestedTNLInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RequestedTNLInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceDataForPaging) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceDataForPaging) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceDataForPaging.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceDataForPaging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceDataForPaging) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceDataForPaging.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceDataForPaging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceDataForRecommendedCells) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceDataForRecommendedCells) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceDataForRecommendedCells.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceDataForRecommendedCells.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceDataForRecommendedCells) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceDataForRecommendedCells.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceDataForRecommendedCells.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RecommendedCellItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RecommendedCellItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RecommendedCellItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedCellItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RecommendedCellItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RecommendedCellItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedCellItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RecommendedCellsForPaging) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RecommendedCellsForPaging) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RecommendedCellsForPaging.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedCellsForPaging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RecommendedCellsForPaging) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RecommendedCellsForPaging.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedCellsForPaging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RequestType) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RequestType) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RequestType.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RequestType.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RequestType) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RequestType.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RequestType.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RequestedTNLInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RequestedTNLInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RequestedTNLInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RequestedTNLInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RequestedTNLInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RequestedTNLInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RequestedTNLInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *AssistanceDataForPaging) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AssistanceDataForPaging")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AssistanceDataForPaging) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceDataForPaging")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAssistanceDataForPaging(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AssistanceDataForPaging")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AssistanceDataForPaging")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AssistanceDataForPaging) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AssistanceDataForPaging")
}
func (v *AssistanceDataForPaging) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AssistanceDataForPaging")
}
func (v *AssistanceDataForPaging) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAssistanceDataForPaging(v, &s)
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
func (v *AssistanceDataForPaging) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AssistanceDataForPaging) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AssistanceDataForRecommendedCells) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AssistanceDataForRecommendedCells")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AssistanceDataForRecommendedCells) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceDataForRecommendedCells")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAssistanceDataForRecommendedCells(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AssistanceDataForRecommendedCells")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AssistanceDataForRecommendedCells")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AssistanceDataForRecommendedCells) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AssistanceDataForRecommendedCells")
}
func (v *AssistanceDataForRecommendedCells) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AssistanceDataForRecommendedCells")
}
func (v *AssistanceDataForRecommendedCells) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAssistanceDataForRecommendedCells(v, &s)
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
func (v *AssistanceDataForRecommendedCells) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AssistanceDataForRecommendedCells) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RecommendedCellItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RecommendedCellItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RecommendedCellItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RecommendedCellItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRecommendedCellItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RecommendedCellItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RecommendedCellItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RecommendedCellItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RecommendedCellItem")
}
func (v *RecommendedCellItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RecommendedCellItem")
}
func (v *RecommendedCellItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRecommendedCellItem(v, &s)
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
func (v *RecommendedCellItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RecommendedCellItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RecommendedCellsForPaging) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RecommendedCellsForPaging")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RecommendedCellsForPaging) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RecommendedCellsForPaging")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRecommendedCellsForPaging(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RecommendedCellsForPaging")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RecommendedCellsForPaging")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RecommendedCellsForPaging) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RecommendedCellsForPaging")
}
func (v *RecommendedCellsForPaging) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RecommendedCellsForPaging")
}
func (v *RecommendedCellsForPaging) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRecommendedCellsForPaging(v, &s)
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
func (v *RecommendedCellsForPaging) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RecommendedCellsForPaging) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RequestType) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RequestType")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RequestType) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RequestType")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRequestType(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RequestType")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RequestType")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RequestType) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RequestType")
}
func (v *RequestType) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RequestType")
}
func (v *RequestType) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRequestType(v, &s)
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
func (v *RequestType) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RequestType) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RequestedTNLInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RequestedTNLInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RequestedTNLInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RequestedTNLInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRequestedTNLInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RequestedTNLInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RequestedTNLInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RequestedTNLInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RequestedTNLInfo")
}
func (v *RequestedTNLInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RequestedTNLInfo")
}
func (v *RequestedTNLInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRequestedTNLInfo(v, &s)
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
func (v *RequestedTNLInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RequestedTNLInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AssistanceDataForPaging) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceDataForPaging")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AssistanceDataForPaging
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAssistanceDataForPaging(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AssistanceDataForPaging{}
		return report, aper.OperationError(err, "AssistanceDataForPaging")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceDataForPaging")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *AssistanceDataForRecommendedCells) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceDataForRecommendedCells")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AssistanceDataForRecommendedCells
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAssistanceDataForRecommendedCells(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AssistanceDataForRecommendedCells{}
		return report, aper.OperationError(err, "AssistanceDataForRecommendedCells")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceDataForRecommendedCells")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RecommendedCellItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RecommendedCellItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RecommendedCellItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRecommendedCellItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RecommendedCellItem{}
		return report, aper.OperationError(err, "RecommendedCellItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RecommendedCellItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RecommendedCellsForPaging) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RecommendedCellsForPaging")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RecommendedCellsForPaging
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRecommendedCellsForPaging(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RecommendedCellsForPaging{}
		return report, aper.OperationError(err, "RecommendedCellsForPaging")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RecommendedCellsForPaging")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RequestType) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RequestType")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RequestType
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRequestType(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RequestType{}
		return report, aper.OperationError(err, "RequestType")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RequestType")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RequestedTNLInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RequestedTNLInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RequestedTNLInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRequestedTNLInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RequestedTNLInfo{}
		return report, aper.OperationError(err, "RequestedTNLInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RequestedTNLInfo")
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
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12(v s14.COUNTvalue, options ...aper.BuildOption) (s15.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12Legacy(v)
	if _, err := s15.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15 constructs a checked complete value.
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15(v s14.COUNTValueExtended, options ...aper.BuildOption) (s15.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15Legacy(v)
	if _, err := s15.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18 constructs a checked complete value.
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18(v s14.COUNTvaluePDCPSNlength18, options ...aper.BuildOption) (s15.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18Legacy(v)
	if _, err := s15.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
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

// NewLastVisitedGERANCellInformationUndefined constructs a checked complete value.
func NewLastVisitedGERANCellInformationUndefined(v struct{}, options ...aper.BuildOption) (s18.LastVisitedGERANCellInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUndefined")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUndefined")
	}
	value := BridgeNewLastVisitedGERANCellInformationUndefinedLegacy(v)
	if _, err := s18.BridgeLastVisitedGERANCellInformationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUndefined")
	}
	return value, aper.OperationError(nil, "LastVisitedGERANCellInformationUndefined")
}

// NewLoggedMDTTriggerPeriodical constructs a checked complete value.
func NewLoggedMDTTriggerPeriodical(v struct{}, options ...aper.BuildOption) (s19.LoggedMDTTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerPeriodical")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerPeriodical")
	}
	value := BridgeNewLoggedMDTTriggerPeriodicalLegacy(v)
	if _, err := s19.BridgeLoggedMDTTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerPeriodical")
	}
	return value, aper.OperationError(nil, "LoggedMDTTriggerPeriodical")
}

// NewLoggedMDTTriggerEventTrigger constructs a checked complete value.
func NewLoggedMDTTriggerEventTrigger(v s19.EventTrigger, options ...aper.BuildOption) (s19.LoggedMDTTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerEventTrigger")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerEventTrigger")
	}
	value := BridgeNewLoggedMDTTriggerEventTriggerLegacy(v)
	if _, err := s19.BridgeLoggedMDTTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerEventTrigger")
	}
	return value, aper.OperationError(nil, "LoggedMDTTriggerEventTrigger")
}

// NewMeasurementThresholdA2ThresholdRSRP constructs a checked complete value.
func NewMeasurementThresholdA2ThresholdRSRP(v s00.ThresholdRSRP, options ...aper.BuildOption) (s19.MeasurementThresholdA2, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRP")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRP")
	}
	value := BridgeNewMeasurementThresholdA2ThresholdRSRPLegacy(v)
	if _, err := s19.BridgeMeasurementThresholdA2MethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRP")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdA2ThresholdRSRP")
}

// NewMeasurementThresholdA2ThresholdRSRQ constructs a checked complete value.
func NewMeasurementThresholdA2ThresholdRSRQ(v s00.ThresholdRSRQ, options ...aper.BuildOption) (s19.MeasurementThresholdA2, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRQ")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRQ")
	}
	value := BridgeNewMeasurementThresholdA2ThresholdRSRQLegacy(v)
	if _, err := s19.BridgeMeasurementThresholdA2MethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRQ")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdA2ThresholdRSRQ")
}

// NewMeasurementThresholdL1LoggedMDTThresholdRSRP constructs a checked complete value.
func NewMeasurementThresholdL1LoggedMDTThresholdRSRP(v s00.ThresholdRSRP, options ...aper.BuildOption) (s19.MeasurementThresholdL1LoggedMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRP")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRP")
	}
	value := BridgeNewMeasurementThresholdL1LoggedMDTThresholdRSRPLegacy(v)
	if _, err := s19.BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRP")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdL1LoggedMDTThresholdRSRP")
}

// NewMeasurementThresholdL1LoggedMDTThresholdRSRQ constructs a checked complete value.
func NewMeasurementThresholdL1LoggedMDTThresholdRSRQ(v s00.ThresholdRSRQ, options ...aper.BuildOption) (s19.MeasurementThresholdL1LoggedMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRQ")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRQ")
	}
	value := BridgeNewMeasurementThresholdL1LoggedMDTThresholdRSRQLegacy(v)
	if _, err := s19.BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRQ")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdL1LoggedMDTThresholdRSRQ")
}

// NewMeasurementThresholdL1LoggedMDTChoiceExtensions constructs a checked complete value.
func NewMeasurementThresholdL1LoggedMDTChoiceExtensions(v s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer, options ...aper.BuildOption) (s19.MeasurementThresholdL1LoggedMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTChoiceExtensions")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTChoiceExtensions")
	}
	value := BridgeNewMeasurementThresholdL1LoggedMDTChoiceExtensionsLegacy(v)
	if _, err := s19.BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTChoiceExtensions")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdL1LoggedMDTChoiceExtensions")
}

// NewOverloadResponseOverloadAction constructs a checked complete value.
func NewOverloadResponseOverloadAction(v s00.OverloadAction, options ...aper.BuildOption) (s20.OverloadResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.OverloadResponse{}, aper.OperationError(err, "OverloadResponseOverloadAction")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.OverloadResponse{}, aper.OperationError(err, "OverloadResponseOverloadAction")
	}
	value := BridgeNewOverloadResponseOverloadActionLegacy(v)
	if _, err := s20.BridgeOverloadResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.OverloadResponse{}, aper.OperationError(err, "OverloadResponseOverloadAction")
	}
	return value, aper.OperationError(nil, "OverloadResponseOverloadAction")
}

// NewSONInformationReportRLFReportInformation constructs a checked complete value.
func NewSONInformationReportRLFReportInformation(v s20.RLFReportInformation, options ...aper.BuildOption) (s20.SONInformationReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.SONInformationReport{}, aper.OperationError(err, "SONInformationReportRLFReportInformation")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.SONInformationReport{}, aper.OperationError(err, "SONInformationReportRLFReportInformation")
	}
	value := BridgeNewSONInformationReportRLFReportInformationLegacy(v)
	if _, err := s20.BridgeSONInformationReportMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.SONInformationReport{}, aper.OperationError(err, "SONInformationReportRLFReportInformation")
	}
	return value, aper.OperationError(nil, "SONInformationReportRLFReportInformation")
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

// PathSwitchRequestFailure represents the ASN.1 type PathSwitchRequestFailure (SEQUENCE).
type PathSwitchRequestFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s23.PathSwitchRequestFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
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

// LocationReportingControl represents the ASN.1 type LocationReportingControl (SEQUENCE).
type LocationReportingControl struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      LocationReportingControlIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                `asn1:"-" json:"-"`
	extCount         int64                               `asn1:"-" json:"-"`
	extPresent       []bool                              `asn1:"-" json:"-"`
	extData          [][]byte                            `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                   `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding              `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// PrivateMessage represents the ASN.1 type PrivateMessage (SEQUENCE).
type PrivateMessage struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	PrivateIEs       s25.PrivateMessageIEsValuePrivateIEContainer `asn1:"tag:0,context,implicit"`
	privateIEsIndef  bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
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

// MarshalAPER encodes PathSwitchRequestFailure to APER format.
func (v *PathSwitchRequestFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PathSwitchRequestFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PathSwitchRequestFailure from APER format.
func (v *PathSwitchRequestFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PathSwitchRequestFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PathSwitchRequestFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestFailure")
	}
	bb.EnterComponent("PathSwitchRequestFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "PathSwitchRequestFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PathSwitchRequestFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s23.PathSwitchRequestFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.PathSwitchRequestFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABToBeModifiedListBearerModReqTo appends a ERABToBeModifiedListBearerModReq list to bb.
func BridgeMarshalAPERERABToBeModifiedListBearerModReqTo(list s25.ERABToBeModifiedListBearerModReq, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABToBeModifiedListBearerModReqListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s25.BridgeERABToBeModifiedItemBearerModReqIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
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
			if err := s17.BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
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

// MarshalAPER encodes LocationReportingControl to APER format.
func (v *LocationReportingControl) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LocationReportingControl) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes LocationReportingControl from APER format.
func (v *LocationReportingControl) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LocationReportingControl with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LocationReportingControl) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingControl")
	}
	bb.EnterComponent("LocationReportingControl")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingControl")
	}
	padding, err := aper.CaptureFinalBits(bb, "LocationReportingControl")
	if err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingControl")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LocationReportingControl) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LocationReportingControl{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(LocationReportingControlIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem LocationReportingControlIEField
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

// MarshalAPER encodes PrivateMessage to APER format.
func (v *PrivateMessage) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PrivateMessage) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.PrivateIEs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_privateies < 0 || fragmentOffset_privateies > int64(len(v.PrivateIEs)) || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(len(v.PrivateIEs[fragmentOffset_privateies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PrivateIEs[fragmentOffset_privateies : fragmentOffset_privateies+fragmentLength_privateies] {
			if err := s25.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding privateIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding privateIEs: %w", err)
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

// UnmarshalAPER decodes PrivateMessage from APER format.
func (v *PrivateMessage) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PrivateMessage with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PrivateMessage) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	bb.EnterComponent("PrivateMessage")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	padding, err := aper.CaptureFinalBits(bb, "PrivateMessage")
	if err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PrivateMessage) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateMessage{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_privateies := bb.EnterComponent("PrivateIEs")
	v.PrivateIEs = make(s25.PrivateMessageIEsValuePrivateIEContainer, 0)
	_, errCollection_privateies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_privateies < 0 || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(^uint(0)>>1) || fragmentOffset_privateies > int64(^uint(0)>>1)-fragmentLength_privateies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_privateies; i++ {
			var elem s25.PrivateMessageIEsValuePrivateIEField
			elementMark := bb.EnterIndex(fragmentOffset_privateies + i)
			if err := s25.BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PrivateIEs[%d]", fragmentOffset_privateies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.PrivateIEs, elem); err != nil {
				return err
			} else {
				v.PrivateIEs = next
			}
		}
		return nil
	})
	if errCollection_privateies != nil {
		return runtime.WrapDecodePath(errCollection_privateies, "PrivateIEs")
	}
	bb.LeaveComponent(toleranceMark_privateies)
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
			if err := s16.BridgeERABFailedToResumeItemResumeResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func (v *LocationReportingControl) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LocationReportingControl", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LocationReportingControl", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LocationReportingControl) WithoutReplay() LocationReportingControl {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LocationReportingControl
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PathSwitchRequestFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PathSwitchRequestFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PathSwitchRequestFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PathSwitchRequestFailure) WithoutReplay() PathSwitchRequestFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PathSwitchRequestFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PrivateMessage) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PrivateMessage", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PrivateMessage", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PrivateMessage) WithoutReplay() PrivateMessage {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PrivateMessage
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *LocationReportingControl) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LocationReportingControl) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LocationReportingControl.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LocationReportingControl.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LocationReportingControl) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LocationReportingControl.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LocationReportingControl.Extensions[%d]", index))
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

// Extensions returns owned unknown sequence additions.
func (v *PathSwitchRequestFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PathSwitchRequestFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PathSwitchRequestFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PathSwitchRequestFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PathSwitchRequestFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PathSwitchRequestFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PathSwitchRequestFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PrivateMessage) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PrivateMessage) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PrivateMessage) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *LocationReportingControl) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LocationReportingControl")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LocationReportingControl) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LocationReportingControl")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLocationReportingControl(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LocationReportingControl")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LocationReportingControl")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LocationReportingControl) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LocationReportingControl")
}
func (v *LocationReportingControl) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LocationReportingControl")
}
func (v *LocationReportingControl) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLocationReportingControl(v, &s)
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
func (v *LocationReportingControl) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LocationReportingControl) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PathSwitchRequestFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PathSwitchRequestFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PathSwitchRequestFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPathSwitchRequestFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PathSwitchRequestFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PathSwitchRequestFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PathSwitchRequestFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PathSwitchRequestFailure")
}
func (v *PathSwitchRequestFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PathSwitchRequestFailure")
}
func (v *PathSwitchRequestFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPathSwitchRequestFailure(v, &s)
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
func (v *PathSwitchRequestFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PathSwitchRequestFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PrivateMessage) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PrivateMessage")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PrivateMessage) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PrivateMessage")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPrivateMessage(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PrivateMessage")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PrivateMessage")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PrivateMessage) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PrivateMessage")
}
func (v *PrivateMessage) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PrivateMessage")
}
func (v *PrivateMessage) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPrivateMessage(v, &s)
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
func (v *PrivateMessage) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PrivateMessage) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LocationReportingControl) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LocationReportingControl")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LocationReportingControl
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLocationReportingControl(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LocationReportingControl{}
		return report, aper.OperationError(err, "LocationReportingControl")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LocationReportingControl")
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PathSwitchRequestFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PathSwitchRequestFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PathSwitchRequestFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPathSwitchRequestFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PathSwitchRequestFailure{}
		return report, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PathSwitchRequestFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PrivateMessage) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PrivateMessage")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PrivateMessage
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPrivateMessage(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PrivateMessage{}
		return report, aper.OperationError(err, "PrivateMessage")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PrivateMessage")
}

// NewSONtransferRequestContainerCellLoadReporting creates a SONtransferRequestContainer with the cellLoadReporting alternative.
func BridgeNewSONtransferRequestContainerCellLoadReportingLegacy(v struct{}) s24.SONtransferRequestContainer {
	return s24.SONtransferRequestContainer{
		Choice:            s00.SONtransferRequestContainerChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerMultiCellLoadReporting creates a SONtransferRequestContainer with the multiCellLoadReporting alternative.
func BridgeNewSONtransferRequestContainerMultiCellLoadReportingLegacy(v s24.MultiCellLoadReportingRequest) s24.SONtransferRequestContainer {
	return s24.SONtransferRequestContainer{
		Choice:                 s00.SONtransferRequestContainerChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerEventTriggeredCellLoadReporting creates a SONtransferRequestContainer with the eventTriggeredCellLoadReporting alternative.
func BridgeNewSONtransferRequestContainerEventTriggeredCellLoadReportingLegacy(v s18.EventTriggeredCellLoadReportingRequest) s24.SONtransferRequestContainer {
	return s24.SONtransferRequestContainer{
		Choice:                          s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerHOReporting creates a SONtransferRequestContainer with the hOReporting alternative.
func BridgeNewSONtransferRequestContainerHOReportingLegacy(v s22.HOReport) s24.SONtransferRequestContainer {
	return s24.SONtransferRequestContainer{
		Choice:      s00.SONtransferRequestContainerChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferRequestContainerEutranCellActivation creates a SONtransferRequestContainer with the eutranCellActivation alternative.
func BridgeNewSONtransferRequestContainerEutranCellActivationLegacy(v s22.CellActivationRequest) s24.SONtransferRequestContainer {
	return s24.SONtransferRequestContainer{
		Choice:               s00.SONtransferRequestContainerChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferRequestContainerEnergySavingsIndication creates a SONtransferRequestContainer with the energySavingsIndication alternative.
func BridgeNewSONtransferRequestContainerEnergySavingsIndicationLegacy(v s24.CellStateIndication) s24.SONtransferRequestContainer {
	return s24.SONtransferRequestContainer{
		Choice:                  s00.SONtransferRequestContainerChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferRequestContainerFailureEventReporting creates a SONtransferRequestContainer with the failureEventReporting alternative.
func BridgeNewSONtransferRequestContainerFailureEventReportingLegacy(v s21.FailureEventReport) s24.SONtransferRequestContainer {
	return s24.SONtransferRequestContainer{
		Choice:                s00.SONtransferRequestContainerChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// NewSONtransferResponseContainerCellLoadReporting creates a SONtransferResponseContainer with the cellLoadReporting alternative.
func BridgeNewSONtransferResponseContainerCellLoadReportingLegacy(v s18.CellLoadReportingResponse) s24.SONtransferResponseContainer {
	return s24.SONtransferResponseContainer{
		Choice:            s00.SONtransferResponseContainerChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferResponseContainerMultiCellLoadReporting creates a SONtransferResponseContainer with the multiCellLoadReporting alternative.
func BridgeNewSONtransferResponseContainerMultiCellLoadReportingLegacy(v s19.MultiCellLoadReportingResponse) s24.SONtransferResponseContainer {
	return s24.SONtransferResponseContainer{
		Choice:                 s00.SONtransferResponseContainerChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: v,
	}
}

// NewSONtransferResponseContainerEventTriggeredCellLoadReporting creates a SONtransferResponseContainer with the eventTriggeredCellLoadReporting alternative.
func BridgeNewSONtransferResponseContainerEventTriggeredCellLoadReportingLegacy(v s18.EventTriggeredCellLoadReportingResponse) s24.SONtransferResponseContainer {
	return s24.SONtransferResponseContainer{
		Choice:                          s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferResponseContainerHOReporting creates a SONtransferResponseContainer with the hOReporting alternative.
func BridgeNewSONtransferResponseContainerHOReportingLegacy(v struct{}) s24.SONtransferResponseContainer {
	return s24.SONtransferResponseContainer{
		Choice:      s00.SONtransferResponseContainerChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferResponseContainerEutranCellActivation creates a SONtransferResponseContainer with the eutranCellActivation alternative.
func BridgeNewSONtransferResponseContainerEutranCellActivationLegacy(v s21.CellActivationResponse) s24.SONtransferResponseContainer {
	return s24.SONtransferResponseContainer{
		Choice:               s00.SONtransferResponseContainerChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferResponseContainerEnergySavingsIndication creates a SONtransferResponseContainer with the energySavingsIndication alternative.
func BridgeNewSONtransferResponseContainerEnergySavingsIndicationLegacy(v struct{}) s24.SONtransferResponseContainer {
	return s24.SONtransferResponseContainer{
		Choice:                  s00.SONtransferResponseContainerChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferResponseContainerFailureEventReporting creates a SONtransferResponseContainer with the failureEventReporting alternative.
func BridgeNewSONtransferResponseContainerFailureEventReportingLegacy(v struct{}) s24.SONtransferResponseContainer {
	return s24.SONtransferResponseContainer{
		Choice:                s00.SONtransferResponseContainerChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// NewSONtransferCauseCellLoadReporting creates a SONtransferCause with the cellLoadReporting alternative.
func BridgeNewSONtransferCauseCellLoadReportingLegacy(v s00.CellLoadReportingCause) s20.SONtransferCause {
	return s20.SONtransferCause{
		Choice:            s00.SONtransferCauseChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferCauseMultiCellLoadReporting creates a SONtransferCause with the multiCellLoadReporting alternative.
func BridgeNewSONtransferCauseMultiCellLoadReportingLegacy(v s00.CellLoadReportingCause) s20.SONtransferCause {
	return s20.SONtransferCause{
		Choice:                 s00.SONtransferCauseChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: &v,
	}
}

// NewSONtransferCauseEventTriggeredCellLoadReporting creates a SONtransferCause with the eventTriggeredCellLoadReporting alternative.
func BridgeNewSONtransferCauseEventTriggeredCellLoadReportingLegacy(v s00.CellLoadReportingCause) s20.SONtransferCause {
	return s20.SONtransferCause{
		Choice:                          s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferCauseHOReporting creates a SONtransferCause with the hOReporting alternative.
func BridgeNewSONtransferCauseHOReportingLegacy(v s00.HOReportingCause) s20.SONtransferCause {
	return s20.SONtransferCause{
		Choice:      s00.SONtransferCauseChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferCauseEutranCellActivation creates a SONtransferCause with the eutranCellActivation alternative.
func BridgeNewSONtransferCauseEutranCellActivationLegacy(v s00.CellActivationCause) s20.SONtransferCause {
	return s20.SONtransferCause{
		Choice:               s00.SONtransferCauseChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferCauseEnergySavingsIndication creates a SONtransferCause with the energySavingsIndication alternative.
func BridgeNewSONtransferCauseEnergySavingsIndicationLegacy(v s00.CellStateIndicationCause) s20.SONtransferCause {
	return s20.SONtransferCause{
		Choice:                  s00.SONtransferCauseChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferCauseFailureEventReporting creates a SONtransferCause with the failureEventReporting alternative.
func BridgeNewSONtransferCauseFailureEventReportingLegacy(v s00.FailureEventReportingCause) s20.SONtransferCause {
	return s20.SONtransferCause{
		Choice:                s00.SONtransferCauseChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// NewCellLoadReportingResponseEUTRAN creates a CellLoadReportingResponse with the eUTRAN alternative.
func BridgeNewCellLoadReportingResponseEUTRANLegacy(v s18.EUTRANcellLoadReportingResponse) s18.CellLoadReportingResponse {
	return s18.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceEUTRAN,
		EUTRAN: &v,
	}
}

// NewCellLoadReportingResponseUTRAN creates a CellLoadReportingResponse with the uTRAN alternative.
func BridgeNewCellLoadReportingResponseUTRANLegacy(v []byte) s18.CellLoadReportingResponse {
	return s18.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceUTRAN,
		UTRAN:  v,
	}
}

// NewCellLoadReportingResponseGERAN creates a CellLoadReportingResponse with the gERAN alternative.
func BridgeNewCellLoadReportingResponseGERANLegacy(v []byte) s18.CellLoadReportingResponse {
	return s18.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceGERAN,
		GERAN:  v,
	}
}

// NewCellLoadReportingResponseEHRPD creates a CellLoadReportingResponse with the eHRPD alternative.
func BridgeNewCellLoadReportingResponseEHRPDLegacy(v s15.EHRPDSectorLoadReportingResponse) s18.CellLoadReportingResponse {
	return s18.CellLoadReportingResponse{
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

// NewIRATCellIDUTRAN creates a IRATCellID with the uTRAN alternative.
func BridgeNewIRATCellIDUTRANLegacy(v []byte) s18.IRATCellID {
	return s18.IRATCellID{
		Choice: s00.IRATCellIDChoiceUTRAN,
		UTRAN:  v,
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

// NewMultiCellLoadReportingResponseItemEUTRANResponse creates a MultiCellLoadReportingResponseItem with the eUTRANResponse alternative.
func BridgeNewMultiCellLoadReportingResponseItemEUTRANResponseLegacy(v s18.EUTRANResponse) s19.MultiCellLoadReportingResponseItem {
	return s19.MultiCellLoadReportingResponseItem{
		Choice:         s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse,
		EUTRANResponse: &v,
	}
}

// NewMultiCellLoadReportingResponseItemUTRANResponse creates a MultiCellLoadReportingResponseItem with the uTRANResponse alternative.
func BridgeNewMultiCellLoadReportingResponseItemUTRANResponseLegacy(v []byte) s19.MultiCellLoadReportingResponseItem {
	return s19.MultiCellLoadReportingResponseItem{
		Choice:        s00.MultiCellLoadReportingResponseItemChoiceUTRANResponse,
		UTRANResponse: v,
	}
}

// NewMultiCellLoadReportingResponseItemGERANResponse creates a MultiCellLoadReportingResponseItem with the gERANResponse alternative.
func BridgeNewMultiCellLoadReportingResponseItemGERANResponseLegacy(v []byte) s19.MultiCellLoadReportingResponseItem {
	return s19.MultiCellLoadReportingResponseItem{
		Choice:        s00.MultiCellLoadReportingResponseItemChoiceGERANResponse,
		GERANResponse: v,
	}
}

// NewMultiCellLoadReportingResponseItemEHRPD creates a MultiCellLoadReportingResponseItem with the eHRPD alternative.
func BridgeNewMultiCellLoadReportingResponseItemEHRPDLegacy(v s15.EHRPDMultiSectorLoadReportingResponseItem) s19.MultiCellLoadReportingResponseItem {
	return s19.MultiCellLoadReportingResponseItem{
		Choice: s00.MultiCellLoadReportingResponseItemChoiceEHRPD,
		EHRPD:  &v,
	}
}

// NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN creates a FailureEventReport with the tooEarlyInterRATHOReportFromEUTRAN alternative.
func BridgeNewFailureEventReportTooEarlyInterRATHOReportFromEUTRANLegacy(v s21.TooEarlyInterRATHOReportReportFromEUTRAN) s21.FailureEventReport {
	return s21.FailureEventReport{
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

// NewSONtransferRequestContainerCellLoadReporting constructs a checked complete value.
func NewSONtransferRequestContainerCellLoadReporting(v struct{}, options ...aper.BuildOption) (s24.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerCellLoadReporting")
	}
	value := BridgeNewSONtransferRequestContainerCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerCellLoadReporting")
}

// NewSONtransferRequestContainerMultiCellLoadReporting constructs a checked complete value.
func NewSONtransferRequestContainerMultiCellLoadReporting(v s24.MultiCellLoadReportingRequest, options ...aper.BuildOption) (s24.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerMultiCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerMultiCellLoadReporting")
	}
	value := BridgeNewSONtransferRequestContainerMultiCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerMultiCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerMultiCellLoadReporting")
}

// NewSONtransferRequestContainerEventTriggeredCellLoadReporting constructs a checked complete value.
func NewSONtransferRequestContainerEventTriggeredCellLoadReporting(v s18.EventTriggeredCellLoadReportingRequest, options ...aper.BuildOption) (s24.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEventTriggeredCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEventTriggeredCellLoadReporting")
	}
	value := BridgeNewSONtransferRequestContainerEventTriggeredCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEventTriggeredCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerEventTriggeredCellLoadReporting")
}

// NewSONtransferRequestContainerHOReporting constructs a checked complete value.
func NewSONtransferRequestContainerHOReporting(v s22.HOReport, options ...aper.BuildOption) (s24.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerHOReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerHOReporting")
	}
	value := BridgeNewSONtransferRequestContainerHOReportingLegacy(v)
	if _, err := s24.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerHOReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerHOReporting")
}

// NewSONtransferRequestContainerEutranCellActivation constructs a checked complete value.
func NewSONtransferRequestContainerEutranCellActivation(v s22.CellActivationRequest, options ...aper.BuildOption) (s24.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEutranCellActivation")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEutranCellActivation")
	}
	value := BridgeNewSONtransferRequestContainerEutranCellActivationLegacy(v)
	if _, err := s24.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEutranCellActivation")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerEutranCellActivation")
}

// NewSONtransferRequestContainerEnergySavingsIndication constructs a checked complete value.
func NewSONtransferRequestContainerEnergySavingsIndication(v s24.CellStateIndication, options ...aper.BuildOption) (s24.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEnergySavingsIndication")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEnergySavingsIndication")
	}
	value := BridgeNewSONtransferRequestContainerEnergySavingsIndicationLegacy(v)
	if _, err := s24.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEnergySavingsIndication")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerEnergySavingsIndication")
}

// NewSONtransferRequestContainerFailureEventReporting constructs a checked complete value.
func NewSONtransferRequestContainerFailureEventReporting(v s21.FailureEventReport, options ...aper.BuildOption) (s24.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerFailureEventReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerFailureEventReporting")
	}
	value := BridgeNewSONtransferRequestContainerFailureEventReportingLegacy(v)
	if _, err := s24.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerFailureEventReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerFailureEventReporting")
}

// NewSONtransferResponseContainerCellLoadReporting constructs a checked complete value.
func NewSONtransferResponseContainerCellLoadReporting(v s18.CellLoadReportingResponse, options ...aper.BuildOption) (s24.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerCellLoadReporting")
	}
	value := BridgeNewSONtransferResponseContainerCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerCellLoadReporting")
}

// NewSONtransferResponseContainerMultiCellLoadReporting constructs a checked complete value.
func NewSONtransferResponseContainerMultiCellLoadReporting(v s19.MultiCellLoadReportingResponse, options ...aper.BuildOption) (s24.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerMultiCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerMultiCellLoadReporting")
	}
	value := BridgeNewSONtransferResponseContainerMultiCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerMultiCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerMultiCellLoadReporting")
}

// NewSONtransferResponseContainerEventTriggeredCellLoadReporting constructs a checked complete value.
func NewSONtransferResponseContainerEventTriggeredCellLoadReporting(v s18.EventTriggeredCellLoadReportingResponse, options ...aper.BuildOption) (s24.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEventTriggeredCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEventTriggeredCellLoadReporting")
	}
	value := BridgeNewSONtransferResponseContainerEventTriggeredCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEventTriggeredCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerEventTriggeredCellLoadReporting")
}

// NewSONtransferResponseContainerHOReporting constructs a checked complete value.
func NewSONtransferResponseContainerHOReporting(v struct{}, options ...aper.BuildOption) (s24.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerHOReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerHOReporting")
	}
	value := BridgeNewSONtransferResponseContainerHOReportingLegacy(v)
	if _, err := s24.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerHOReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerHOReporting")
}

// NewSONtransferResponseContainerEutranCellActivation constructs a checked complete value.
func NewSONtransferResponseContainerEutranCellActivation(v s21.CellActivationResponse, options ...aper.BuildOption) (s24.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEutranCellActivation")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEutranCellActivation")
	}
	value := BridgeNewSONtransferResponseContainerEutranCellActivationLegacy(v)
	if _, err := s24.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEutranCellActivation")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerEutranCellActivation")
}

// NewSONtransferResponseContainerEnergySavingsIndication constructs a checked complete value.
func NewSONtransferResponseContainerEnergySavingsIndication(v struct{}, options ...aper.BuildOption) (s24.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEnergySavingsIndication")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEnergySavingsIndication")
	}
	value := BridgeNewSONtransferResponseContainerEnergySavingsIndicationLegacy(v)
	if _, err := s24.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEnergySavingsIndication")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerEnergySavingsIndication")
}

// NewSONtransferResponseContainerFailureEventReporting constructs a checked complete value.
func NewSONtransferResponseContainerFailureEventReporting(v struct{}, options ...aper.BuildOption) (s24.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerFailureEventReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerFailureEventReporting")
	}
	value := BridgeNewSONtransferResponseContainerFailureEventReportingLegacy(v)
	if _, err := s24.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerFailureEventReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerFailureEventReporting")
}

// NewSONtransferCauseCellLoadReporting constructs a checked complete value.
func NewSONtransferCauseCellLoadReporting(v s00.CellLoadReportingCause, options ...aper.BuildOption) (s20.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseCellLoadReporting")
	}
	value := BridgeNewSONtransferCauseCellLoadReportingLegacy(v)
	if _, err := s20.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseCellLoadReporting")
}

// NewSONtransferCauseMultiCellLoadReporting constructs a checked complete value.
func NewSONtransferCauseMultiCellLoadReporting(v s00.CellLoadReportingCause, options ...aper.BuildOption) (s20.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseMultiCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseMultiCellLoadReporting")
	}
	value := BridgeNewSONtransferCauseMultiCellLoadReportingLegacy(v)
	if _, err := s20.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseMultiCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseMultiCellLoadReporting")
}

// NewSONtransferCauseEventTriggeredCellLoadReporting constructs a checked complete value.
func NewSONtransferCauseEventTriggeredCellLoadReporting(v s00.CellLoadReportingCause, options ...aper.BuildOption) (s20.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEventTriggeredCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEventTriggeredCellLoadReporting")
	}
	value := BridgeNewSONtransferCauseEventTriggeredCellLoadReportingLegacy(v)
	if _, err := s20.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEventTriggeredCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseEventTriggeredCellLoadReporting")
}

// NewSONtransferCauseHOReporting constructs a checked complete value.
func NewSONtransferCauseHOReporting(v s00.HOReportingCause, options ...aper.BuildOption) (s20.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseHOReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseHOReporting")
	}
	value := BridgeNewSONtransferCauseHOReportingLegacy(v)
	if _, err := s20.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseHOReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseHOReporting")
}

// NewSONtransferCauseEutranCellActivation constructs a checked complete value.
func NewSONtransferCauseEutranCellActivation(v s00.CellActivationCause, options ...aper.BuildOption) (s20.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEutranCellActivation")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEutranCellActivation")
	}
	value := BridgeNewSONtransferCauseEutranCellActivationLegacy(v)
	if _, err := s20.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEutranCellActivation")
	}
	return value, aper.OperationError(nil, "SONtransferCauseEutranCellActivation")
}

// NewSONtransferCauseEnergySavingsIndication constructs a checked complete value.
func NewSONtransferCauseEnergySavingsIndication(v s00.CellStateIndicationCause, options ...aper.BuildOption) (s20.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEnergySavingsIndication")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEnergySavingsIndication")
	}
	value := BridgeNewSONtransferCauseEnergySavingsIndicationLegacy(v)
	if _, err := s20.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEnergySavingsIndication")
	}
	return value, aper.OperationError(nil, "SONtransferCauseEnergySavingsIndication")
}

// NewSONtransferCauseFailureEventReporting constructs a checked complete value.
func NewSONtransferCauseFailureEventReporting(v s00.FailureEventReportingCause, options ...aper.BuildOption) (s20.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseFailureEventReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseFailureEventReporting")
	}
	value := BridgeNewSONtransferCauseFailureEventReportingLegacy(v)
	if _, err := s20.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s20.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseFailureEventReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseFailureEventReporting")
}

// NewCellLoadReportingResponseEUTRAN constructs a checked complete value.
func NewCellLoadReportingResponseEUTRAN(v s18.EUTRANcellLoadReportingResponse, options ...aper.BuildOption) (s18.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	value := BridgeNewCellLoadReportingResponseEUTRANLegacy(v)
	if _, err := s18.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseEUTRAN")
}

// NewCellLoadReportingResponseUTRAN constructs a checked complete value.
func NewCellLoadReportingResponseUTRAN(v []byte, options ...aper.BuildOption) (s18.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	value := BridgeNewCellLoadReportingResponseUTRANLegacy(v)
	if _, err := s18.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseUTRAN")
}

// NewCellLoadReportingResponseGERAN constructs a checked complete value.
func NewCellLoadReportingResponseGERAN(v []byte, options ...aper.BuildOption) (s18.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	value := BridgeNewCellLoadReportingResponseGERANLegacy(v)
	if _, err := s18.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseGERAN")
}

// NewCellLoadReportingResponseEHRPD constructs a checked complete value.
func NewCellLoadReportingResponseEHRPD(v s15.EHRPDSectorLoadReportingResponse, options ...aper.BuildOption) (s18.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
	}
	value := BridgeNewCellLoadReportingResponseEHRPDLegacy(v)
	if _, err := s18.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
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

// NewIRATCellIDUTRAN constructs a checked complete value.
func NewIRATCellIDUTRAN(v []byte, options ...aper.BuildOption) (s18.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDUTRAN")
	}
	value := BridgeNewIRATCellIDUTRANLegacy(v)
	if _, err := s18.BridgeIRATCellIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDUTRAN")
	}
	return value, aper.OperationError(nil, "IRATCellIDUTRAN")
}

// NewIRATCellIDGERAN constructs a checked complete value.
func NewIRATCellIDGERAN(v []byte, options ...aper.BuildOption) (s18.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDGERAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDGERAN")
	}
	value := BridgeNewIRATCellIDGERANLegacy(v)
	if _, err := s18.BridgeIRATCellIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDGERAN")
	}
	return value, aper.OperationError(nil, "IRATCellIDGERAN")
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

// NewMultiCellLoadReportingResponseItemEUTRANResponse constructs a checked complete value.
func NewMultiCellLoadReportingResponseItemEUTRANResponse(v s18.EUTRANResponse, options ...aper.BuildOption) (s19.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEUTRANResponse")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEUTRANResponse")
	}
	value := BridgeNewMultiCellLoadReportingResponseItemEUTRANResponseLegacy(v)
	if _, err := s19.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEUTRANResponse")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemEUTRANResponse")
}

// NewMultiCellLoadReportingResponseItemUTRANResponse constructs a checked complete value.
func NewMultiCellLoadReportingResponseItemUTRANResponse(v []byte, options ...aper.BuildOption) (s19.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUTRANResponse")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUTRANResponse")
	}
	value := BridgeNewMultiCellLoadReportingResponseItemUTRANResponseLegacy(v)
	if _, err := s19.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUTRANResponse")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemUTRANResponse")
}

// NewMultiCellLoadReportingResponseItemGERANResponse constructs a checked complete value.
func NewMultiCellLoadReportingResponseItemGERANResponse(v []byte, options ...aper.BuildOption) (s19.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemGERANResponse")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemGERANResponse")
	}
	value := BridgeNewMultiCellLoadReportingResponseItemGERANResponseLegacy(v)
	if _, err := s19.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemGERANResponse")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemGERANResponse")
}

// NewMultiCellLoadReportingResponseItemEHRPD constructs a checked complete value.
func NewMultiCellLoadReportingResponseItemEHRPD(v s15.EHRPDMultiSectorLoadReportingResponseItem, options ...aper.BuildOption) (s19.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEHRPD")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEHRPD")
	}
	value := BridgeNewMultiCellLoadReportingResponseItemEHRPDLegacy(v)
	if _, err := s19.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEHRPD")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemEHRPD")
}

// NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN constructs a checked complete value.
func NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN(v s21.TooEarlyInterRATHOReportReportFromEUTRAN, options ...aper.BuildOption) (s21.FailureEventReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
	}
	value := BridgeNewFailureEventReportTooEarlyInterRATHOReportFromEUTRANLegacy(v)
	if _, err := s21.BridgeFailureEventReportMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
	}
	return value, aper.OperationError(nil, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
}

type RecommendedCellItemIEValue struct {
	id                     s00.ProtocolIEID
	received               aper.WireSpan
	replay                 aper.Snapshot
	opaque                 aper.OpaqueOpenType
	isOpaque               bool
	rowRecommendedCellItem *RecommendedCellItem
}

func (v RecommendedCellItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(214):
		return v.rowRecommendedCellItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of RecommendedCellItemIEValue and reports whether the opaque alternative is selected.
func (v *RecommendedCellItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (RecommendedCellItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RecommendedCellItemIEs"}}
}
func (RecommendedCellItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(214):
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

// AsRecommendedCellItem returns the selected RecommendedCellItem value of RecommendedCellItemIEValue and reports whether that alternative is active.
func (v *RecommendedCellItemIEValue) AsRecommendedCellItem() (*RecommendedCellItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(214) || v.rowRecommendedCellItem == nil {
		return nil, false
	}
	return v.rowRecommendedCellItem, true
}
func (v RecommendedCellItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (RecommendedCellItemIEValue, error) {
	out := RecommendedCellItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(214):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value RecommendedCellItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "RecommendedCellItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RecommendedCellItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowRecommendedCellItem = &value
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
func (v RecommendedCellItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v RecommendedCellItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(214):
		if v.rowRecommendedCellItem == nil {
			return nil, fmt.Errorf("%s missing value", "RecommendedCellItemIEs.id-RecommendedCellItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowRecommendedCellItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "RecommendedCellItemIEValue:", v.id)
	}
}

type LocationReportingControlIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
	rowRequestType *RequestType
}

func (v LocationReportingControlIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(98):
		return v.rowRequestType != nil
	}
	return false
}

// Opaque returns the retained opaque open value of LocationReportingControlIEValue and reports whether the opaque alternative is selected.
func (v *LocationReportingControlIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (LocationReportingControlIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingControlIEs"}}
}
func (LocationReportingControlIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(98):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of LocationReportingControlIEValue and reports whether that alternative is active.
func (v *LocationReportingControlIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of LocationReportingControlIEValue and reports whether that alternative is active.
func (v *LocationReportingControlIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsRequestType returns the selected RequestType value of LocationReportingControlIEValue and reports whether that alternative is active.
func (v *LocationReportingControlIEValue) AsRequestType() (*RequestType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(98) || v.rowRequestType == nil {
		return nil, false
	}
	return v.rowRequestType, true
}
func (v LocationReportingControlIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (LocationReportingControlIEValue, error) {
	out := LocationReportingControlIEValue{id: id}
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
	case s00.ProtocolIEID(98):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value RequestType
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "RequestType:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RequestType")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowRequestType = &value
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
func (v LocationReportingControlIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v LocationReportingControlIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "LocationReportingControlIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "LocationReportingControlIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(98):
		if v.rowRequestType == nil {
			return nil, fmt.Errorf("%s missing value", "LocationReportingControlIEs.id-RequestType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowRequestType.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "LocationReportingControlIEValue:", v.id)
	}
}

type RecommendedCellItemIETable struct{}

func RecommendedCellItemIEs() RecommendedCellItemIETable { return RecommendedCellItemIETable{} }

// ID returns the ASN.1 object-set identity of RecommendedCellItemIETable.
func (RecommendedCellItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RecommendedCellItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RecommendedCellItemIETable.
func (RecommendedCellItemIETable) Table() s00.RecommendedCellItemIEValueIETable {
	return func() s00.RecommendedCellItemIEValueIETable {
		sealed := s00.RecommendedCellItemIEValueIETable{}
		*s00.BridgeRecommendedCellItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (RecommendedCellItemIETable) infoRecommendedCellItem() s00.FieldInfo {
	return s00.FieldInfo{Table: RecommendedCellItemIEs().ID(), ID: s00.ProtocolIEID(214), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RecommendedCellItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RecommendedCellItemIEs", Row: "id-RecommendedCellItem"}}}
}

// RecommendedCellItem returns the typed binding for the RecommendedCellItem row of RecommendedCellItemIETable.
func (t RecommendedCellItemIETable) RecommendedCellItem() RecommendedCellItemRecommendedCellItemIEBinding {
	return RecommendedCellItemRecommendedCellItemIEBinding{info: t.infoRecommendedCellItem(), codec: RecommendedCellItemValueCodec{path: "RecommendedCellItem",
		decode: func(data []byte, options aper.DecodeState) (RecommendedCellItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty RecommendedCellItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RecommendedCellItem")
			var zero RecommendedCellItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(214), raw)
			if err != nil {
				var empty RecommendedCellItem
				return empty, runtime.WrapDecodePath(err, "RecommendedCellItem")
			}
			value, ok := decoded.AsRecommendedCellItem()
			if !ok {
				var empty RecommendedCellItem
				return empty, fmt.Errorf("binding RecommendedCellItemIEs.id-RecommendedCellItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value RecommendedCellItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (RecommendedCellItemIEValue{id: s00.ProtocolIEID(214), rowRecommendedCellItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v RecommendedCellItem, options aper.DecodeState) (RecommendedCellItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APRecommendedCellItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v RecommendedCellItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APRecommendedCellItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RecommendedCellItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value RecommendedCellItem) RecommendedCellItemIEValue {
		return RecommendedCellItemIEValue{id: s00.ProtocolIEID(214), rowRecommendedCellItem: &value}
	}, get: func(value *RecommendedCellItemIEValue) (*RecommendedCellItem, bool) {
		return value.AsRecommendedCellItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RecommendedCellItemIETable.
func (t RecommendedCellItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (RecommendedCellItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RecommendedCellItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(214):
		return RecommendedCellItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-RecommendedCellItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RecommendedCellItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RecommendedCellItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return RecommendedCellItemIEField{Id: id, Criticality: criticality, Value: RecommendedCellItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type LocationReportingControlIETable struct{}

func LocationReportingControlIEs() LocationReportingControlIETable {
	return LocationReportingControlIETable{}
}

// ID returns the ASN.1 object-set identity of LocationReportingControlIETable.
func (LocationReportingControlIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingControlIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LocationReportingControlIETable.
func (LocationReportingControlIETable) Table() s00.LocationReportingControlIEValueIETable {
	return func() s00.LocationReportingControlIEValueIETable {
		sealed := s00.LocationReportingControlIEValueIETable{}
		*s00.BridgeLocationReportingControlIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (LocationReportingControlIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportingControlIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingControlIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of LocationReportingControlIETable.
func (t LocationReportingControlIETable) MMEUES1APID() LocationReportingControlMMEUES1APIDIEBinding {
	return LocationReportingControlMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero LocationReportingControlIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding LocationReportingControlIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LocationReportingControlIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) LocationReportingControlIEValue {
			return LocationReportingControlIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *LocationReportingControlIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (LocationReportingControlIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportingControlIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingControlIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of LocationReportingControlIETable.
func (t LocationReportingControlIETable) ENBUES1APID() LocationReportingControlENBUES1APIDIEBinding {
	return LocationReportingControlENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero LocationReportingControlIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding LocationReportingControlIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LocationReportingControlIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) LocationReportingControlIEValue {
			return LocationReportingControlIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *LocationReportingControlIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (LocationReportingControlIETable) infoRequestType() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportingControlIEs().ID(), ID: s00.ProtocolIEID(98), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingControlIEs", Row: "id-RequestType"}}}
}

// RequestType returns the typed binding for the RequestType row of LocationReportingControlIETable.
func (t LocationReportingControlIETable) RequestType() LocationReportingControlRequestTypeIEBinding {
	return LocationReportingControlRequestTypeIEBinding{info: t.infoRequestType(), codec: RequestTypeValueCodec{path: "RequestType",
		decode: func(data []byte, options aper.DecodeState) (RequestType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty RequestType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RequestType")
			var zero LocationReportingControlIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(98), raw)
			if err != nil {
				var empty RequestType
				return empty, runtime.WrapDecodePath(err, "RequestType")
			}
			value, ok := decoded.AsRequestType()
			if !ok {
				var empty RequestType
				return empty, fmt.Errorf("binding LocationReportingControlIEs.id-RequestType: no selected value")
			}
			return *value, nil
		},
		encode: func(value RequestType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LocationReportingControlIEValue{id: s00.ProtocolIEID(98), rowRequestType: &value}).encodeFresh(fresh, budget)
		}, capture: func(v RequestType, options aper.DecodeState) (RequestType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APRequestType(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v RequestType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APRequestType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RequestType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value RequestType) LocationReportingControlIEValue {
		return LocationReportingControlIEValue{id: s00.ProtocolIEID(98), rowRequestType: &value}
	}, get: func(value *LocationReportingControlIEValue) (*RequestType, bool) { return value.AsRequestType() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LocationReportingControlIETable.
func (t LocationReportingControlIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (LocationReportingControlIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(98):
		return LocationReportingControlIEField{}, aper.OperationError(fmt.Errorf("known IE id-RequestType requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return LocationReportingControlIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return LocationReportingControlIEField{}, aper.OperationError(err, "Opaque")
		}
		return LocationReportingControlIEField{Id: id, Criticality: criticality, Value: LocationReportingControlIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AssistanceDataForRecommendedCellsCodec binds the complete source value type.
func AssistanceDataForRecommendedCellsCodec() AssistanceDataForRecommendedCellsValueCodec {
	return AssistanceDataForRecommendedCellsValueCodec{path: "AssistanceDataForRecommendedCells", decode: func(data []byte, options aper.DecodeState) (AssistanceDataForRecommendedCells, error) {
		var value AssistanceDataForRecommendedCells
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AssistanceDataForRecommendedCells{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AssistanceDataForRecommendedCells, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AssistanceDataForRecommendedCells, options aper.DecodeState) (AssistanceDataForRecommendedCells, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APAssistanceDataForRecommendedCells(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v AssistanceDataForRecommendedCells, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APAssistanceDataForRecommendedCells(
			&v,

			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceDataForRecommendedCells"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// RecommendedCellItemCodec binds the complete APER value type.
func RecommendedCellItemCodec() RecommendedCellItemValueCodec {
	return RecommendedCellItemIEs().RecommendedCellItem().Codec()
}

// RecommendedCellsForPagingCodec binds the complete source value type.
func RecommendedCellsForPagingCodec() RecommendedCellsForPagingValueCodec {
	return RecommendedCellsForPagingValueCodec{path: "RecommendedCellsForPaging", decode: func(data []byte, options aper.DecodeState) (RecommendedCellsForPaging, error) {
		var value RecommendedCellsForPaging
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return RecommendedCellsForPaging{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value RecommendedCellsForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v RecommendedCellsForPaging, options aper.DecodeState) (RecommendedCellsForPaging, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APRecommendedCellsForPaging(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v RecommendedCellsForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APRecommendedCellsForPaging(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RecommendedCellsForPaging"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
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
func BridgeAssistanceDataForPagingAPERValueFieldContext(v *AssistanceDataForPagingAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceDataForPagingAPERValueFieldReceived(v *AssistanceDataForPagingAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceDataForPagingAPERValueFieldReplay(v *AssistanceDataForPagingAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceDataForPagingAPERValueFieldWithoutReplay(v *AssistanceDataForPagingAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceDataForPagingFieldExtCount(v *AssistanceDataForPaging) *int64 {
	return &v.extCount
}
func BridgeAssistanceDataForPagingFieldExtData(v *AssistanceDataForPaging) *[][]byte {
	return &v.extData
}
func BridgeAssistanceDataForPagingFieldExtOrigin(v *AssistanceDataForPaging) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceDataForPagingFieldExtPresent(v *AssistanceDataForPaging) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceDataForPagingFieldExtWire(v *AssistanceDataForPaging) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeAssistanceDataForPagingFieldIEExtensionsIndef(v *AssistanceDataForPaging) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAssistanceDataForPagingFieldPerExtPadding(v *AssistanceDataForPaging) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceDataForPagingFieldPerPadding(v *AssistanceDataForPaging) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceDataForPagingFieldReceived(v *AssistanceDataForPaging) *bool { return &v.received }
func BridgeAssistanceDataForPagingFieldReceivedAbsolute(v *AssistanceDataForPaging) *bool {
	return &v.receivedAbsolute
}
func BridgeAssistanceDataForPagingFieldReceivedBytes(v *AssistanceDataForPaging) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceDataForPagingFieldReceivedLocation(v *AssistanceDataForPaging) *aper.Location {
	return &v.receivedLocation
}
func BridgeAssistanceDataForPagingFieldReplay(v *AssistanceDataForPaging) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceDataForPagingFieldStream(v *AssistanceDataForPaging) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceDataForPagingFieldWithoutReplay(v *AssistanceDataForPaging) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceDataForPagingMethodMarshalAPERBudget(v *AssistanceDataForPaging, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceDataForPagingMethodMarshalAPERBudgetValue(v *AssistanceDataForPaging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeAssistanceDataForPagingMethodMarshalAPERChanged(v *AssistanceDataForPaging, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceDataForPagingMethodMarshalAPERChangedValue(v *AssistanceDataForPaging, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceDataForPagingMethodMarshalAPERLegacy(v *AssistanceDataForPaging) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceDataForPagingMethodMarshalAPERNewValue(v *AssistanceDataForPaging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeAssistanceDataForPagingMethodMarshalAPERPlanned(v *AssistanceDataForPaging, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeAssistanceDataForPagingMethodMarshalAPERTo(v *AssistanceDataForPaging, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceDataForPagingMethodUnmarshalAPERFrom(v *AssistanceDataForPaging, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceDataForPagingMethodUnmarshalAPERLegacy(v *AssistanceDataForPaging, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceDataForPagingMethodUnmarshalAPERWithOptions(v *AssistanceDataForPaging, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceDataForPagingValueCodecFieldCapture(v *AssistanceDataForPagingValueCodec) *func(AssistanceDataForPaging, aper.DecodeState) (AssistanceDataForPaging, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceDataForPagingValueCodecFieldCompare(v *AssistanceDataForPagingValueCodec) *func(AssistanceDataForPaging, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAssistanceDataForPagingValueCodecFieldContext(v *AssistanceDataForPagingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceDataForPagingValueCodecFieldDecode(v *AssistanceDataForPagingValueCodec) *func([]byte, aper.DecodeState) (AssistanceDataForPaging, error) {
	return &v.decode
}
func BridgeAssistanceDataForPagingValueCodecFieldEncode(v *AssistanceDataForPagingValueCodec) *func(AssistanceDataForPaging, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceDataForPagingValueCodecFieldPath(v *AssistanceDataForPagingValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceDataForPagingValueCodecMethodEncodeBudgetValue(v AssistanceDataForPagingValueCodec, a0 AssistanceDataForPaging, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeAssistanceDataForPagingValueCodecMethodEncodeChanged(v AssistanceDataForPagingValueCodec, a0 AssistanceDataForPaging, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAssistanceDataForRecommendedCellsAPERValueFieldContext(v *AssistanceDataForRecommendedCellsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceDataForRecommendedCellsAPERValueFieldReceived(v *AssistanceDataForRecommendedCellsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceDataForRecommendedCellsAPERValueFieldReplay(v *AssistanceDataForRecommendedCellsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceDataForRecommendedCellsAPERValueFieldWithoutReplay(v *AssistanceDataForRecommendedCellsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceDataForRecommendedCellsFieldExtCount(v *AssistanceDataForRecommendedCells) *int64 {
	return &v.extCount
}
func BridgeAssistanceDataForRecommendedCellsFieldExtData(v *AssistanceDataForRecommendedCells) *[][]byte {
	return &v.extData
}
func BridgeAssistanceDataForRecommendedCellsFieldExtOrigin(v *AssistanceDataForRecommendedCells) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceDataForRecommendedCellsFieldExtPresent(v *AssistanceDataForRecommendedCells) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceDataForRecommendedCellsFieldExtWire(v *AssistanceDataForRecommendedCells) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeAssistanceDataForRecommendedCellsFieldIEExtensionsIndef(v *AssistanceDataForRecommendedCells) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAssistanceDataForRecommendedCellsFieldPerExtPadding(v *AssistanceDataForRecommendedCells) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceDataForRecommendedCellsFieldPerPadding(v *AssistanceDataForRecommendedCells) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceDataForRecommendedCellsFieldReceived(v *AssistanceDataForRecommendedCells) *bool {
	return &v.received
}
func BridgeAssistanceDataForRecommendedCellsFieldReceivedAbsolute(v *AssistanceDataForRecommendedCells) *bool {
	return &v.receivedAbsolute
}
func BridgeAssistanceDataForRecommendedCellsFieldReceivedBytes(v *AssistanceDataForRecommendedCells) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceDataForRecommendedCellsFieldReceivedLocation(v *AssistanceDataForRecommendedCells) *aper.Location {
	return &v.receivedLocation
}
func BridgeAssistanceDataForRecommendedCellsFieldReplay(v *AssistanceDataForRecommendedCells) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceDataForRecommendedCellsFieldStream(v *AssistanceDataForRecommendedCells) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceDataForRecommendedCellsFieldWithoutReplay(v *AssistanceDataForRecommendedCells) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceDataForRecommendedCellsMethodMarshalAPERBudget(v *AssistanceDataForRecommendedCells, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceDataForRecommendedCellsMethodMarshalAPERBudgetValue(v *AssistanceDataForRecommendedCells, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeAssistanceDataForRecommendedCellsMethodMarshalAPERChanged(v *AssistanceDataForRecommendedCells, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceDataForRecommendedCellsMethodMarshalAPERChangedValue(v *AssistanceDataForRecommendedCells, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceDataForRecommendedCellsMethodMarshalAPERLegacy(v *AssistanceDataForRecommendedCells) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceDataForRecommendedCellsMethodMarshalAPERNewValue(v *AssistanceDataForRecommendedCells, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeAssistanceDataForRecommendedCellsMethodMarshalAPERPlanned(v *AssistanceDataForRecommendedCells, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeAssistanceDataForRecommendedCellsMethodMarshalAPERTo(v *AssistanceDataForRecommendedCells, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceDataForRecommendedCellsMethodUnmarshalAPERFrom(v *AssistanceDataForRecommendedCells, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceDataForRecommendedCellsMethodUnmarshalAPERLegacy(v *AssistanceDataForRecommendedCells, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceDataForRecommendedCellsMethodUnmarshalAPERWithOptions(v *AssistanceDataForRecommendedCells, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceDataForRecommendedCellsValueCodecFieldCapture(v *AssistanceDataForRecommendedCellsValueCodec) *func(AssistanceDataForRecommendedCells, aper.DecodeState) (AssistanceDataForRecommendedCells, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceDataForRecommendedCellsValueCodecFieldCompare(v *AssistanceDataForRecommendedCellsValueCodec) *func(AssistanceDataForRecommendedCells, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAssistanceDataForRecommendedCellsValueCodecFieldContext(v *AssistanceDataForRecommendedCellsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceDataForRecommendedCellsValueCodecFieldDecode(v *AssistanceDataForRecommendedCellsValueCodec) *func([]byte, aper.DecodeState) (AssistanceDataForRecommendedCells, error) {
	return &v.decode
}
func BridgeAssistanceDataForRecommendedCellsValueCodecFieldEncode(v *AssistanceDataForRecommendedCellsValueCodec) *func(AssistanceDataForRecommendedCells, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceDataForRecommendedCellsValueCodecFieldPath(v *AssistanceDataForRecommendedCellsValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceDataForRecommendedCellsValueCodecMethodEncodeBudgetValue(v AssistanceDataForRecommendedCellsValueCodec, a0 AssistanceDataForRecommendedCells, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeAssistanceDataForRecommendedCellsValueCodecMethodEncodeChanged(v AssistanceDataForRecommendedCellsValueCodec, a0 AssistanceDataForRecommendedCells, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingControlAPERValueFieldContext(v *LocationReportingControlAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlAPERValueFieldReceived(v *LocationReportingControlAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingControlAPERValueFieldReplay(v *LocationReportingControlAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlAPERValueFieldWithoutReplay(v *LocationReportingControlAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingControlENBUES1APIDIEBindingFieldCodec(v *LocationReportingControlENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeLocationReportingControlENBUES1APIDIEBindingFieldGet(v *LocationReportingControlENBUES1APIDIEBinding) *func(*LocationReportingControlIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeLocationReportingControlENBUES1APIDIEBindingFieldInfo(v *LocationReportingControlENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportingControlENBUES1APIDIEBindingFieldInject(v *LocationReportingControlENBUES1APIDIEBinding) *func(s00.ENBUES1APID) LocationReportingControlIEValue {
	return &v.inject
}
func BridgeLocationReportingControlFieldExtCount(v *LocationReportingControl) *int64 {
	return &v.extCount
}
func BridgeLocationReportingControlFieldExtData(v *LocationReportingControl) *[][]byte {
	return &v.extData
}
func BridgeLocationReportingControlFieldExtOrigin(v *LocationReportingControl) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeLocationReportingControlFieldExtPresent(v *LocationReportingControl) *[]bool {
	return &v.extPresent
}
func BridgeLocationReportingControlFieldExtWire(v *LocationReportingControl) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeLocationReportingControlFieldPerExtPadding(v *LocationReportingControl) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeLocationReportingControlFieldPerPadding(v *LocationReportingControl) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeLocationReportingControlFieldProtocolIEsIndef(v *LocationReportingControl) *bool {
	return &v.protocolIEsIndef
}
func BridgeLocationReportingControlFieldReceived(v *LocationReportingControl) *bool {
	return &v.received
}
func BridgeLocationReportingControlFieldReceivedAbsolute(v *LocationReportingControl) *bool {
	return &v.receivedAbsolute
}
func BridgeLocationReportingControlFieldReceivedBytes(v *LocationReportingControl) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLocationReportingControlFieldReceivedLocation(v *LocationReportingControl) *aper.Location {
	return &v.receivedLocation
}
func BridgeLocationReportingControlFieldReplay(v *LocationReportingControl) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlFieldStream(v *LocationReportingControl) *aper.WireSpan {
	return &v.stream
}
func BridgeLocationReportingControlFieldWithoutReplay(v *LocationReportingControl) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingControlIEContainerAPERValueFieldContext(v *LocationReportingControlIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEContainerAPERValueFieldReceived(v *LocationReportingControlIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingControlIEContainerAPERValueFieldReplay(v *LocationReportingControlIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlIEContainerAPERValueFieldWithoutReplay(v *LocationReportingControlIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingControlIEContainerValueCodecFieldCapture(v *LocationReportingControlIEContainerValueCodec) *func(LocationReportingControlIEContainer, aper.DecodeState) (LocationReportingControlIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingControlIEContainerValueCodecFieldCompare(v *LocationReportingControlIEContainerValueCodec) *func(LocationReportingControlIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingControlIEContainerValueCodecFieldContext(v *LocationReportingControlIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEContainerValueCodecFieldDecode(v *LocationReportingControlIEContainerValueCodec) *func([]byte, aper.DecodeState) (LocationReportingControlIEContainer, error) {
	return &v.decode
}
func BridgeLocationReportingControlIEContainerValueCodecFieldEncode(v *LocationReportingControlIEContainerValueCodec) *func(LocationReportingControlIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingControlIEContainerValueCodecFieldPath(v *LocationReportingControlIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingControlIEContainerValueCodecMethodEncodeBudgetValue(v LocationReportingControlIEContainerValueCodec, a0 LocationReportingControlIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingControlIEContainerValueCodecMethodEncodeChanged(v LocationReportingControlIEContainerValueCodec, a0 LocationReportingControlIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingControlIEFieldAPERValueFieldContext(v *LocationReportingControlIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEFieldAPERValueFieldReceived(v *LocationReportingControlIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingControlIEFieldAPERValueFieldReplay(v *LocationReportingControlIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlIEFieldAPERValueFieldWithoutReplay(v *LocationReportingControlIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingControlIEFieldFieldReceived(v *LocationReportingControlIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeLocationReportingControlIEFieldFieldReplay(v *LocationReportingControlIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlIEFieldFieldStream(v *LocationReportingControlIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeLocationReportingControlIEFieldFieldWithoutReplay(v *LocationReportingControlIEField) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingControlIEFieldMethodMarshalAPERTo(v *LocationReportingControlIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLocationReportingControlIEFieldMethodUnmarshalAPERFrom(v *LocationReportingControlIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLocationReportingControlIEFieldValueCodecFieldCapture(v *LocationReportingControlIEFieldValueCodec) *func(LocationReportingControlIEField, aper.DecodeState) (LocationReportingControlIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingControlIEFieldValueCodecFieldCompare(v *LocationReportingControlIEFieldValueCodec) *func(LocationReportingControlIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingControlIEFieldValueCodecFieldContext(v *LocationReportingControlIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEFieldValueCodecFieldDecode(v *LocationReportingControlIEFieldValueCodec) *func([]byte, aper.DecodeState) (LocationReportingControlIEField, error) {
	return &v.decode
}
func BridgeLocationReportingControlIEFieldValueCodecFieldEncode(v *LocationReportingControlIEFieldValueCodec) *func(LocationReportingControlIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingControlIEFieldValueCodecFieldPath(v *LocationReportingControlIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingControlIEFieldValueCodecMethodEncodeBudgetValue(v LocationReportingControlIEFieldValueCodec, a0 LocationReportingControlIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingControlIEFieldValueCodecMethodEncodeChanged(v LocationReportingControlIEFieldValueCodec, a0 LocationReportingControlIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingControlIETableMethodInfoENBUES1APID(v LocationReportingControlIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeLocationReportingControlIETableMethodInfoMMEUES1APID(v LocationReportingControlIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeLocationReportingControlIETableMethodInfoRequestType(v LocationReportingControlIETable) s00.FieldInfo {
	return v.infoRequestType()
}
func BridgeLocationReportingControlIEValueERABIEContainerListAPERValueFieldContext(v *LocationReportingControlIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEValueERABIEContainerListAPERValueFieldReceived(v *LocationReportingControlIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingControlIEValueERABIEContainerListAPERValueFieldReplay(v *LocationReportingControlIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *LocationReportingControlIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingControlIEValueERABIEContainerListValueCodecFieldCapture(v *LocationReportingControlIEValueERABIEContainerListValueCodec) *func(LocationReportingControlIEValueERABIEContainerList, aper.DecodeState) (LocationReportingControlIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingControlIEValueERABIEContainerListValueCodecFieldCompare(v *LocationReportingControlIEValueERABIEContainerListValueCodec) *func(LocationReportingControlIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingControlIEValueERABIEContainerListValueCodecFieldContext(v *LocationReportingControlIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEValueERABIEContainerListValueCodecFieldDecode(v *LocationReportingControlIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportingControlIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportingControlIEValueERABIEContainerListValueCodecFieldEncode(v *LocationReportingControlIEValueERABIEContainerListValueCodec) *func(LocationReportingControlIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingControlIEValueERABIEContainerListValueCodecFieldPath(v *LocationReportingControlIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingControlIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v LocationReportingControlIEValueERABIEContainerListValueCodec, a0 LocationReportingControlIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingControlIEValueERABIEContainerListValueCodecMethodEncodeChanged(v LocationReportingControlIEValueERABIEContainerListValueCodec, a0 LocationReportingControlIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingControlIEValueFieldId(v *LocationReportingControlIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeLocationReportingControlIEValueFieldIsOpaque(v *LocationReportingControlIEValue) *bool {
	return &v.isOpaque
}
func BridgeLocationReportingControlIEValueFieldOpaque(v *LocationReportingControlIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeLocationReportingControlIEValueFieldReceived(v *LocationReportingControlIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingControlIEValueFieldReplay(v *LocationReportingControlIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlIEValueFieldRowENBUES1APID(v *LocationReportingControlIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeLocationReportingControlIEValueFieldRowMMEUES1APID(v *LocationReportingControlIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeLocationReportingControlIEValueFieldRowRequestType(v *LocationReportingControlIEValue) **RequestType {
	return &v.rowRequestType
}
func BridgeLocationReportingControlIEValueMethodCaptureSemantics(v LocationReportingControlIEValue, a0 aper.SemanticCapture) LocationReportingControlIEValue {
	return v.captureSemantics(a0)
}
func BridgeLocationReportingControlIEValueMethodCompareSemantics(v LocationReportingControlIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeLocationReportingControlIEValueMethodDecode(v LocationReportingControlIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (LocationReportingControlIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeLocationReportingControlIEValueMethodEncode(v LocationReportingControlIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeLocationReportingControlIEValueMethodEncodeFresh(v LocationReportingControlIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeLocationReportingControlIEValueMethodMatchesID(v LocationReportingControlIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeLocationReportingControlIEValueMethodReason(v LocationReportingControlIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeLocationReportingControlIEValueMethodRule(v LocationReportingControlIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *LocationReportingControlIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportingControlIEValueProtocolErrorIEContainerList, aper.DecodeState) (LocationReportingControlIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportingControlIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportingControlIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportingControlIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec, a0 LocationReportingControlIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingControlIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v LocationReportingControlIEValueProtocolErrorIEContainerListValueCodec, a0 LocationReportingControlIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListAPERValueFieldContext(v *LocationReportingControlIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListAPERValueFieldReceived(v *LocationReportingControlIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListAPERValueFieldReplay(v *LocationReportingControlIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *LocationReportingControlIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListValueCodecFieldCapture(v *LocationReportingControlIEValueProtocolIEContainerListValueCodec) *func(LocationReportingControlIEValueProtocolIEContainerList, aper.DecodeState) (LocationReportingControlIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListValueCodecFieldCompare(v *LocationReportingControlIEValueProtocolIEContainerListValueCodec) *func(LocationReportingControlIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListValueCodecFieldContext(v *LocationReportingControlIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListValueCodecFieldDecode(v *LocationReportingControlIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportingControlIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListValueCodecFieldEncode(v *LocationReportingControlIEValueProtocolIEContainerListValueCodec) *func(LocationReportingControlIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListValueCodecFieldPath(v *LocationReportingControlIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v LocationReportingControlIEValueProtocolIEContainerListValueCodec, a0 LocationReportingControlIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingControlIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v LocationReportingControlIEValueProtocolIEContainerListValueCodec, a0 LocationReportingControlIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingControlMMEUES1APIDIEBindingFieldCodec(v *LocationReportingControlMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeLocationReportingControlMMEUES1APIDIEBindingFieldGet(v *LocationReportingControlMMEUES1APIDIEBinding) *func(*LocationReportingControlIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeLocationReportingControlMMEUES1APIDIEBindingFieldInfo(v *LocationReportingControlMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportingControlMMEUES1APIDIEBindingFieldInject(v *LocationReportingControlMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) LocationReportingControlIEValue {
	return &v.inject
}
func BridgeLocationReportingControlMethodMarshalAPERBudget(v *LocationReportingControl, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLocationReportingControlMethodMarshalAPERBudgetValue(v *LocationReportingControl, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLocationReportingControlMethodMarshalAPERChanged(v *LocationReportingControl, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLocationReportingControlMethodMarshalAPERChangedValue(v *LocationReportingControl, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLocationReportingControlMethodMarshalAPERLegacy(v *LocationReportingControl) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLocationReportingControlMethodMarshalAPERNewValue(v *LocationReportingControl, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLocationReportingControlMethodMarshalAPERPlanned(v *LocationReportingControl, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLocationReportingControlMethodMarshalAPERTo(v *LocationReportingControl, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLocationReportingControlMethodUnmarshalAPERFrom(v *LocationReportingControl, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLocationReportingControlMethodUnmarshalAPERLegacy(v *LocationReportingControl, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLocationReportingControlMethodUnmarshalAPERWithOptions(v *LocationReportingControl, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLocationReportingControlRequestTypeIEBindingFieldCodec(v *LocationReportingControlRequestTypeIEBinding) *RequestTypeValueCodec {
	return &v.codec
}
func BridgeLocationReportingControlRequestTypeIEBindingFieldGet(v *LocationReportingControlRequestTypeIEBinding) *func(*LocationReportingControlIEValue) (*RequestType, bool) {
	return &v.get
}
func BridgeLocationReportingControlRequestTypeIEBindingFieldInfo(v *LocationReportingControlRequestTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportingControlRequestTypeIEBindingFieldInject(v *LocationReportingControlRequestTypeIEBinding) *func(RequestType) LocationReportingControlIEValue {
	return &v.inject
}
func BridgeLocationReportingControlValueCodecFieldCapture(v *LocationReportingControlValueCodec) *func(LocationReportingControl, aper.DecodeState) (LocationReportingControl, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingControlValueCodecFieldCompare(v *LocationReportingControlValueCodec) *func(LocationReportingControl, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingControlValueCodecFieldContext(v *LocationReportingControlValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingControlValueCodecFieldDecode(v *LocationReportingControlValueCodec) *func([]byte, aper.DecodeState) (LocationReportingControl, error) {
	return &v.decode
}
func BridgeLocationReportingControlValueCodecFieldEncode(v *LocationReportingControlValueCodec) *func(LocationReportingControl, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingControlValueCodecFieldPath(v *LocationReportingControlValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingControlValueCodecMethodEncodeBudgetValue(v LocationReportingControlValueCodec, a0 LocationReportingControl, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingControlValueCodecMethodEncodeChanged(v LocationReportingControlValueCodec, a0 LocationReportingControl, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgePathSwitchRequestFailureAPERValueFieldContext(v *PathSwitchRequestFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureAPERValueFieldReceived(v *PathSwitchRequestFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestFailureAPERValueFieldReplay(v *PathSwitchRequestFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureAPERValueFieldWithoutReplay(v *PathSwitchRequestFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestFailureFieldExtCount(v *PathSwitchRequestFailure) *int64 {
	return &v.extCount
}
func BridgePathSwitchRequestFailureFieldExtData(v *PathSwitchRequestFailure) *[][]byte {
	return &v.extData
}
func BridgePathSwitchRequestFailureFieldExtOrigin(v *PathSwitchRequestFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePathSwitchRequestFailureFieldExtPresent(v *PathSwitchRequestFailure) *[]bool {
	return &v.extPresent
}
func BridgePathSwitchRequestFailureFieldExtWire(v *PathSwitchRequestFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgePathSwitchRequestFailureFieldPerExtPadding(v *PathSwitchRequestFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePathSwitchRequestFailureFieldPerPadding(v *PathSwitchRequestFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePathSwitchRequestFailureFieldProtocolIEsIndef(v *PathSwitchRequestFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgePathSwitchRequestFailureFieldReceived(v *PathSwitchRequestFailure) *bool {
	return &v.received
}
func BridgePathSwitchRequestFailureFieldReceivedAbsolute(v *PathSwitchRequestFailure) *bool {
	return &v.receivedAbsolute
}
func BridgePathSwitchRequestFailureFieldReceivedBytes(v *PathSwitchRequestFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePathSwitchRequestFailureFieldReceivedLocation(v *PathSwitchRequestFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgePathSwitchRequestFailureFieldReplay(v *PathSwitchRequestFailure) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureFieldStream(v *PathSwitchRequestFailure) *aper.WireSpan {
	return &v.stream
}
func BridgePathSwitchRequestFailureFieldWithoutReplay(v *PathSwitchRequestFailure) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestFailureMethodMarshalAPERBudget(v *PathSwitchRequestFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePathSwitchRequestFailureMethodMarshalAPERBudgetValue(v *PathSwitchRequestFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePathSwitchRequestFailureMethodMarshalAPERChanged(v *PathSwitchRequestFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePathSwitchRequestFailureMethodMarshalAPERChangedValue(v *PathSwitchRequestFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePathSwitchRequestFailureMethodMarshalAPERLegacy(v *PathSwitchRequestFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePathSwitchRequestFailureMethodMarshalAPERNewValue(v *PathSwitchRequestFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePathSwitchRequestFailureMethodMarshalAPERPlanned(v *PathSwitchRequestFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePathSwitchRequestFailureMethodMarshalAPERTo(v *PathSwitchRequestFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePathSwitchRequestFailureMethodUnmarshalAPERFrom(v *PathSwitchRequestFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePathSwitchRequestFailureMethodUnmarshalAPERLegacy(v *PathSwitchRequestFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePathSwitchRequestFailureMethodUnmarshalAPERWithOptions(v *PathSwitchRequestFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePathSwitchRequestFailureValueCodecFieldCapture(v *PathSwitchRequestFailureValueCodec) *func(PathSwitchRequestFailure, aper.DecodeState) (PathSwitchRequestFailure, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestFailureValueCodecFieldCompare(v *PathSwitchRequestFailureValueCodec) *func(PathSwitchRequestFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestFailureValueCodecFieldContext(v *PathSwitchRequestFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureValueCodecFieldDecode(v *PathSwitchRequestFailureValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestFailure, error) {
	return &v.decode
}
func BridgePathSwitchRequestFailureValueCodecFieldEncode(v *PathSwitchRequestFailureValueCodec) *func(PathSwitchRequestFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestFailureValueCodecFieldPath(v *PathSwitchRequestFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestFailureValueCodecMethodEncodeBudgetValue(v PathSwitchRequestFailureValueCodec, a0 PathSwitchRequestFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestFailureValueCodecMethodEncodeChanged(v PathSwitchRequestFailureValueCodec, a0 PathSwitchRequestFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateMessageAPERValueFieldContext(v *PrivateMessageAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageAPERValueFieldReceived(v *PrivateMessageAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePrivateMessageAPERValueFieldReplay(v *PrivateMessageAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePrivateMessageAPERValueFieldWithoutReplay(v *PrivateMessageAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageFieldExtCount(v *PrivateMessage) *int64                { return &v.extCount }
func BridgePrivateMessageFieldExtData(v *PrivateMessage) *[][]byte              { return &v.extData }
func BridgePrivateMessageFieldExtOrigin(v *PrivateMessage) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgePrivateMessageFieldExtPresent(v *PrivateMessage) *[]bool             { return &v.extPresent }
func BridgePrivateMessageFieldExtWire(v *PrivateMessage) *[]aper.WireSpan       { return &v.extWire }
func BridgePrivateMessageFieldPerExtPadding(v *PrivateMessage) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePrivateMessageFieldPerPadding(v *PrivateMessage) *aper.FinalPadding { return &v.perPadding }
func BridgePrivateMessageFieldPrivateIEsIndef(v *PrivateMessage) *bool         { return &v.privateIEsIndef }
func BridgePrivateMessageFieldReceived(v *PrivateMessage) *bool                { return &v.received }
func BridgePrivateMessageFieldReceivedAbsolute(v *PrivateMessage) *bool        { return &v.receivedAbsolute }
func BridgePrivateMessageFieldReceivedBytes(v *PrivateMessage) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePrivateMessageFieldReceivedLocation(v *PrivateMessage) *aper.Location {
	return &v.receivedLocation
}
func BridgePrivateMessageFieldReplay(v *PrivateMessage) *aper.Snapshot { return &v.replay }
func BridgePrivateMessageFieldStream(v *PrivateMessage) *aper.WireSpan { return &v.stream }
func BridgePrivateMessageFieldWithoutReplay(v *PrivateMessage) *bool   { return &v.withoutReplay }
func BridgePrivateMessageMethodMarshalAPERBudget(v *PrivateMessage, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERBudgetValue(v *PrivateMessage, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERChanged(v *PrivateMessage, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePrivateMessageMethodMarshalAPERChangedValue(v *PrivateMessage, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePrivateMessageMethodMarshalAPERLegacy(v *PrivateMessage) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePrivateMessageMethodMarshalAPERNewValue(v *PrivateMessage, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERPlanned(v *PrivateMessage, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePrivateMessageMethodMarshalAPERTo(v *PrivateMessage, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateMessageMethodUnmarshalAPERFrom(v *PrivateMessage, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePrivateMessageMethodUnmarshalAPERLegacy(v *PrivateMessage, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePrivateMessageMethodUnmarshalAPERWithOptions(v *PrivateMessage, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePrivateMessageValueCodecFieldCapture(v *PrivateMessageValueCodec) *func(PrivateMessage, aper.DecodeState) (PrivateMessage, aper.Snapshot) {
	return &v.capture
}
func BridgePrivateMessageValueCodecFieldCompare(v *PrivateMessageValueCodec) *func(PrivateMessage, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePrivateMessageValueCodecFieldContext(v *PrivateMessageValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageValueCodecFieldDecode(v *PrivateMessageValueCodec) *func([]byte, aper.DecodeState) (PrivateMessage, error) {
	return &v.decode
}
func BridgePrivateMessageValueCodecFieldEncode(v *PrivateMessageValueCodec) *func(PrivateMessage, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateMessageValueCodecFieldPath(v *PrivateMessageValueCodec) *aper.Path { return &v.path }
func BridgePrivateMessageValueCodecMethodEncodeBudgetValue(v PrivateMessageValueCodec, a0 PrivateMessage, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePrivateMessageValueCodecMethodEncodeChanged(v PrivateMessageValueCodec, a0 PrivateMessage, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedCellItemAPERValueFieldContext(v *RecommendedCellItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemAPERValueFieldReceived(v *RecommendedCellItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellItemAPERValueFieldReplay(v *RecommendedCellItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellItemAPERValueFieldWithoutReplay(v *RecommendedCellItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellItemFieldExtCount(v *RecommendedCellItem) *int64   { return &v.extCount }
func BridgeRecommendedCellItemFieldExtData(v *RecommendedCellItem) *[][]byte { return &v.extData }
func BridgeRecommendedCellItemFieldExtOrigin(v *RecommendedCellItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRecommendedCellItemFieldExtPresent(v *RecommendedCellItem) *[]bool { return &v.extPresent }
func BridgeRecommendedCellItemFieldExtWire(v *RecommendedCellItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeRecommendedCellItemFieldIEExtensionsIndef(v *RecommendedCellItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeRecommendedCellItemFieldPerExtPadding(v *RecommendedCellItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRecommendedCellItemFieldPerPadding(v *RecommendedCellItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRecommendedCellItemFieldReceived(v *RecommendedCellItem) *bool { return &v.received }
func BridgeRecommendedCellItemFieldReceivedAbsolute(v *RecommendedCellItem) *bool {
	return &v.receivedAbsolute
}
func BridgeRecommendedCellItemFieldReceivedBytes(v *RecommendedCellItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRecommendedCellItemFieldReceivedLocation(v *RecommendedCellItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeRecommendedCellItemFieldReplay(v *RecommendedCellItem) *aper.Snapshot { return &v.replay }
func BridgeRecommendedCellItemFieldStream(v *RecommendedCellItem) *aper.WireSpan { return &v.stream }
func BridgeRecommendedCellItemFieldWithoutReplay(v *RecommendedCellItem) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellItemIEContainerAPERValueFieldContext(v *RecommendedCellItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEContainerAPERValueFieldReceived(v *RecommendedCellItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellItemIEContainerAPERValueFieldReplay(v *RecommendedCellItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellItemIEContainerAPERValueFieldWithoutReplay(v *RecommendedCellItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellItemIEContainerValueCodecFieldCapture(v *RecommendedCellItemIEContainerValueCodec) *func(RecommendedCellItemIEContainer, aper.DecodeState) (RecommendedCellItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellItemIEContainerValueCodecFieldCompare(v *RecommendedCellItemIEContainerValueCodec) *func(RecommendedCellItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellItemIEContainerValueCodecFieldContext(v *RecommendedCellItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEContainerValueCodecFieldDecode(v *RecommendedCellItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellItemIEContainer, error) {
	return &v.decode
}
func BridgeRecommendedCellItemIEContainerValueCodecFieldEncode(v *RecommendedCellItemIEContainerValueCodec) *func(RecommendedCellItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellItemIEContainerValueCodecFieldPath(v *RecommendedCellItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellItemIEContainerValueCodecMethodEncodeBudgetValue(v RecommendedCellItemIEContainerValueCodec, a0 RecommendedCellItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedCellItemIEContainerValueCodecMethodEncodeChanged(v RecommendedCellItemIEContainerValueCodec, a0 RecommendedCellItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedCellItemIEFieldAPERValueFieldContext(v *RecommendedCellItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEFieldAPERValueFieldReceived(v *RecommendedCellItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellItemIEFieldAPERValueFieldReplay(v *RecommendedCellItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellItemIEFieldAPERValueFieldWithoutReplay(v *RecommendedCellItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellItemIEFieldFieldReceived(v *RecommendedCellItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeRecommendedCellItemIEFieldFieldReplay(v *RecommendedCellItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellItemIEFieldFieldStream(v *RecommendedCellItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeRecommendedCellItemIEFieldFieldWithoutReplay(v *RecommendedCellItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellItemIEFieldMethodMarshalAPERTo(v *RecommendedCellItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedCellItemIEFieldMethodUnmarshalAPERFrom(v *RecommendedCellItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedCellItemIEFieldValueCodecFieldCapture(v *RecommendedCellItemIEFieldValueCodec) *func(RecommendedCellItemIEField, aper.DecodeState) (RecommendedCellItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellItemIEFieldValueCodecFieldCompare(v *RecommendedCellItemIEFieldValueCodec) *func(RecommendedCellItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellItemIEFieldValueCodecFieldContext(v *RecommendedCellItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEFieldValueCodecFieldDecode(v *RecommendedCellItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellItemIEField, error) {
	return &v.decode
}
func BridgeRecommendedCellItemIEFieldValueCodecFieldEncode(v *RecommendedCellItemIEFieldValueCodec) *func(RecommendedCellItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellItemIEFieldValueCodecFieldPath(v *RecommendedCellItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellItemIEFieldValueCodecMethodEncodeBudgetValue(v RecommendedCellItemIEFieldValueCodec, a0 RecommendedCellItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedCellItemIEFieldValueCodecMethodEncodeChanged(v RecommendedCellItemIEFieldValueCodec, a0 RecommendedCellItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedCellItemIETableMethodInfoRecommendedCellItem(v RecommendedCellItemIETable) s00.FieldInfo {
	return v.infoRecommendedCellItem()
}
func BridgeRecommendedCellItemIEValueERABIEContainerListAPERValueFieldContext(v *RecommendedCellItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEValueERABIEContainerListAPERValueFieldReceived(v *RecommendedCellItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellItemIEValueERABIEContainerListAPERValueFieldReplay(v *RecommendedCellItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *RecommendedCellItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellItemIEValueERABIEContainerListValueCodecFieldCapture(v *RecommendedCellItemIEValueERABIEContainerListValueCodec) *func(RecommendedCellItemIEValueERABIEContainerList, aper.DecodeState) (RecommendedCellItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellItemIEValueERABIEContainerListValueCodecFieldCompare(v *RecommendedCellItemIEValueERABIEContainerListValueCodec) *func(RecommendedCellItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellItemIEValueERABIEContainerListValueCodecFieldContext(v *RecommendedCellItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEValueERABIEContainerListValueCodecFieldDecode(v *RecommendedCellItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeRecommendedCellItemIEValueERABIEContainerListValueCodecFieldEncode(v *RecommendedCellItemIEValueERABIEContainerListValueCodec) *func(RecommendedCellItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellItemIEValueERABIEContainerListValueCodecFieldPath(v *RecommendedCellItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v RecommendedCellItemIEValueERABIEContainerListValueCodec, a0 RecommendedCellItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedCellItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v RecommendedCellItemIEValueERABIEContainerListValueCodec, a0 RecommendedCellItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedCellItemIEValueFieldId(v *RecommendedCellItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeRecommendedCellItemIEValueFieldIsOpaque(v *RecommendedCellItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeRecommendedCellItemIEValueFieldOpaque(v *RecommendedCellItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeRecommendedCellItemIEValueFieldReceived(v *RecommendedCellItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellItemIEValueFieldReplay(v *RecommendedCellItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellItemIEValueFieldRowRecommendedCellItem(v *RecommendedCellItemIEValue) **RecommendedCellItem {
	return &v.rowRecommendedCellItem
}
func BridgeRecommendedCellItemIEValueMethodCaptureSemantics(v RecommendedCellItemIEValue, a0 aper.SemanticCapture) RecommendedCellItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeRecommendedCellItemIEValueMethodCompareSemantics(v RecommendedCellItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeRecommendedCellItemIEValueMethodDecode(v RecommendedCellItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (RecommendedCellItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeRecommendedCellItemIEValueMethodEncode(v RecommendedCellItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeRecommendedCellItemIEValueMethodEncodeFresh(v RecommendedCellItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeRecommendedCellItemIEValueMethodMatchesID(v RecommendedCellItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeRecommendedCellItemIEValueMethodReason(v RecommendedCellItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeRecommendedCellItemIEValueMethodRule(v RecommendedCellItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *RecommendedCellItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) *func(RecommendedCellItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (RecommendedCellItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) *func(RecommendedCellItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) *func(RecommendedCellItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec, a0 RecommendedCellItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedCellItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v RecommendedCellItemIEValueProtocolErrorIEContainerListValueCodec, a0 RecommendedCellItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListAPERValueFieldContext(v *RecommendedCellItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *RecommendedCellItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *RecommendedCellItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *RecommendedCellItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *RecommendedCellItemIEValueProtocolIEContainerListValueCodec) *func(RecommendedCellItemIEValueProtocolIEContainerList, aper.DecodeState) (RecommendedCellItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *RecommendedCellItemIEValueProtocolIEContainerListValueCodec) *func(RecommendedCellItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListValueCodecFieldContext(v *RecommendedCellItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *RecommendedCellItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *RecommendedCellItemIEValueProtocolIEContainerListValueCodec) *func(RecommendedCellItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListValueCodecFieldPath(v *RecommendedCellItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v RecommendedCellItemIEValueProtocolIEContainerListValueCodec, a0 RecommendedCellItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedCellItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v RecommendedCellItemIEValueProtocolIEContainerListValueCodec, a0 RecommendedCellItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedCellItemMethodMarshalAPERBudget(v *RecommendedCellItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRecommendedCellItemMethodMarshalAPERBudgetValue(v *RecommendedCellItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRecommendedCellItemMethodMarshalAPERChanged(v *RecommendedCellItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRecommendedCellItemMethodMarshalAPERChangedValue(v *RecommendedCellItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRecommendedCellItemMethodMarshalAPERLegacy(v *RecommendedCellItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRecommendedCellItemMethodMarshalAPERNewValue(v *RecommendedCellItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRecommendedCellItemMethodMarshalAPERPlanned(v *RecommendedCellItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRecommendedCellItemMethodMarshalAPERTo(v *RecommendedCellItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedCellItemMethodUnmarshalAPERFrom(v *RecommendedCellItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedCellItemMethodUnmarshalAPERLegacy(v *RecommendedCellItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRecommendedCellItemMethodUnmarshalAPERWithOptions(v *RecommendedCellItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRecommendedCellItemRecommendedCellItemIEBindingFieldCodec(v *RecommendedCellItemRecommendedCellItemIEBinding) *RecommendedCellItemValueCodec {
	return &v.codec
}
func BridgeRecommendedCellItemRecommendedCellItemIEBindingFieldGet(v *RecommendedCellItemRecommendedCellItemIEBinding) *func(*RecommendedCellItemIEValue) (*RecommendedCellItem, bool) {
	return &v.get
}
func BridgeRecommendedCellItemRecommendedCellItemIEBindingFieldInfo(v *RecommendedCellItemRecommendedCellItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeRecommendedCellItemRecommendedCellItemIEBindingFieldInject(v *RecommendedCellItemRecommendedCellItemIEBinding) *func(RecommendedCellItem) RecommendedCellItemIEValue {
	return &v.inject
}
func BridgeRecommendedCellItemValueCodecFieldCapture(v *RecommendedCellItemValueCodec) *func(RecommendedCellItem, aper.DecodeState) (RecommendedCellItem, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellItemValueCodecFieldCompare(v *RecommendedCellItemValueCodec) *func(RecommendedCellItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellItemValueCodecFieldContext(v *RecommendedCellItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellItemValueCodecFieldDecode(v *RecommendedCellItemValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellItem, error) {
	return &v.decode
}
func BridgeRecommendedCellItemValueCodecFieldEncode(v *RecommendedCellItemValueCodec) *func(RecommendedCellItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellItemValueCodecFieldPath(v *RecommendedCellItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellItemValueCodecMethodEncodeBudgetValue(v RecommendedCellItemValueCodec, a0 RecommendedCellItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedCellItemValueCodecMethodEncodeChanged(v RecommendedCellItemValueCodec, a0 RecommendedCellItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedCellListAPERValueFieldContext(v *RecommendedCellListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellListAPERValueFieldReceived(v *RecommendedCellListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellListAPERValueFieldReplay(v *RecommendedCellListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellListAPERValueFieldWithoutReplay(v *RecommendedCellListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellListValueCodecFieldCapture(v *RecommendedCellListValueCodec) *func(RecommendedCellList, aper.DecodeState) (RecommendedCellList, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellListValueCodecFieldCompare(v *RecommendedCellListValueCodec) *func(RecommendedCellList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellListValueCodecFieldContext(v *RecommendedCellListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellListValueCodecFieldDecode(v *RecommendedCellListValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellList, error) {
	return &v.decode
}
func BridgeRecommendedCellListValueCodecFieldEncode(v *RecommendedCellListValueCodec) *func(RecommendedCellList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellListValueCodecFieldPath(v *RecommendedCellListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellListValueCodecMethodEncodeBudgetValue(v RecommendedCellListValueCodec, a0 RecommendedCellList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedCellListValueCodecMethodEncodeChanged(v RecommendedCellListValueCodec, a0 RecommendedCellList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedCellsForPagingAPERValueFieldContext(v *RecommendedCellsForPagingAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellsForPagingAPERValueFieldReceived(v *RecommendedCellsForPagingAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedCellsForPagingAPERValueFieldReplay(v *RecommendedCellsForPagingAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellsForPagingAPERValueFieldWithoutReplay(v *RecommendedCellsForPagingAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellsForPagingFieldExtCount(v *RecommendedCellsForPaging) *int64 {
	return &v.extCount
}
func BridgeRecommendedCellsForPagingFieldExtData(v *RecommendedCellsForPaging) *[][]byte {
	return &v.extData
}
func BridgeRecommendedCellsForPagingFieldExtOrigin(v *RecommendedCellsForPaging) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRecommendedCellsForPagingFieldExtPresent(v *RecommendedCellsForPaging) *[]bool {
	return &v.extPresent
}
func BridgeRecommendedCellsForPagingFieldExtWire(v *RecommendedCellsForPaging) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeRecommendedCellsForPagingFieldIEExtensionsIndef(v *RecommendedCellsForPaging) *bool {
	return &v.iEExtensionsIndef
}
func BridgeRecommendedCellsForPagingFieldPerExtPadding(v *RecommendedCellsForPaging) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRecommendedCellsForPagingFieldPerPadding(v *RecommendedCellsForPaging) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRecommendedCellsForPagingFieldReceived(v *RecommendedCellsForPaging) *bool {
	return &v.received
}
func BridgeRecommendedCellsForPagingFieldReceivedAbsolute(v *RecommendedCellsForPaging) *bool {
	return &v.receivedAbsolute
}
func BridgeRecommendedCellsForPagingFieldReceivedBytes(v *RecommendedCellsForPaging) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRecommendedCellsForPagingFieldReceivedLocation(v *RecommendedCellsForPaging) *aper.Location {
	return &v.receivedLocation
}
func BridgeRecommendedCellsForPagingFieldRecommendedCellListIndef(v *RecommendedCellsForPaging) *bool {
	return &v.recommendedCellListIndef
}
func BridgeRecommendedCellsForPagingFieldReplay(v *RecommendedCellsForPaging) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellsForPagingFieldStream(v *RecommendedCellsForPaging) *aper.WireSpan {
	return &v.stream
}
func BridgeRecommendedCellsForPagingFieldWithoutReplay(v *RecommendedCellsForPaging) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERBudget(v *RecommendedCellsForPaging, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERBudgetValue(v *RecommendedCellsForPaging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERChanged(v *RecommendedCellsForPaging, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERChangedValue(v *RecommendedCellsForPaging, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERLegacy(v *RecommendedCellsForPaging) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERNewValue(v *RecommendedCellsForPaging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERPlanned(v *RecommendedCellsForPaging, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERTo(v *RecommendedCellsForPaging, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedCellsForPagingMethodUnmarshalAPERFrom(v *RecommendedCellsForPaging, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedCellsForPagingMethodUnmarshalAPERLegacy(v *RecommendedCellsForPaging, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRecommendedCellsForPagingMethodUnmarshalAPERWithOptions(v *RecommendedCellsForPaging, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRecommendedCellsForPagingValueCodecFieldCapture(v *RecommendedCellsForPagingValueCodec) *func(RecommendedCellsForPaging, aper.DecodeState) (RecommendedCellsForPaging, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellsForPagingValueCodecFieldCompare(v *RecommendedCellsForPagingValueCodec) *func(RecommendedCellsForPaging, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellsForPagingValueCodecFieldContext(v *RecommendedCellsForPagingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellsForPagingValueCodecFieldDecode(v *RecommendedCellsForPagingValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellsForPaging, error) {
	return &v.decode
}
func BridgeRecommendedCellsForPagingValueCodecFieldEncode(v *RecommendedCellsForPagingValueCodec) *func(RecommendedCellsForPaging, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellsForPagingValueCodecFieldPath(v *RecommendedCellsForPagingValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellsForPagingValueCodecMethodEncodeBudgetValue(v RecommendedCellsForPagingValueCodec, a0 RecommendedCellsForPaging, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedCellsForPagingValueCodecMethodEncodeChanged(v RecommendedCellsForPagingValueCodec, a0 RecommendedCellsForPaging, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRequestTypeAPERValueFieldContext(v *RequestTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestTypeAPERValueFieldReceived(v *RequestTypeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRequestTypeAPERValueFieldReplay(v *RequestTypeAPERValue) *aper.Snapshot { return &v.replay }
func BridgeRequestTypeAPERValueFieldWithoutReplay(v *RequestTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRequestTypeFieldExtCount(v *RequestType) *int64                { return &v.extCount }
func BridgeRequestTypeFieldExtData(v *RequestType) *[][]byte              { return &v.extData }
func BridgeRequestTypeFieldExtOrigin(v *RequestType) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeRequestTypeFieldExtPresent(v *RequestType) *[]bool             { return &v.extPresent }
func BridgeRequestTypeFieldExtWire(v *RequestType) *[]aper.WireSpan       { return &v.extWire }
func BridgeRequestTypeFieldIEExtensionsIndef(v *RequestType) *bool        { return &v.iEExtensionsIndef }
func BridgeRequestTypeFieldPerExtPadding(v *RequestType) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRequestTypeFieldPerPadding(v *RequestType) *aper.FinalPadding { return &v.perPadding }
func BridgeRequestTypeFieldReceived(v *RequestType) *bool                { return &v.received }
func BridgeRequestTypeFieldReceivedAbsolute(v *RequestType) *bool        { return &v.receivedAbsolute }
func BridgeRequestTypeFieldReceivedBytes(v *RequestType) *aper.WireSpan  { return &v.receivedBytes }
func BridgeRequestTypeFieldReceivedLocation(v *RequestType) *aper.Location {
	return &v.receivedLocation
}
func BridgeRequestTypeFieldReplay(v *RequestType) *aper.Snapshot { return &v.replay }
func BridgeRequestTypeFieldStream(v *RequestType) *aper.WireSpan { return &v.stream }
func BridgeRequestTypeFieldWithoutReplay(v *RequestType) *bool   { return &v.withoutReplay }
func BridgeRequestTypeMethodMarshalAPERBudget(v *RequestType, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRequestTypeMethodMarshalAPERBudgetValue(v *RequestType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRequestTypeMethodMarshalAPERChanged(v *RequestType, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRequestTypeMethodMarshalAPERChangedValue(v *RequestType, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRequestTypeMethodMarshalAPERLegacy(v *RequestType) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRequestTypeMethodMarshalAPERNewValue(v *RequestType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRequestTypeMethodMarshalAPERPlanned(v *RequestType, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRequestTypeMethodMarshalAPERTo(v *RequestType, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRequestTypeMethodUnmarshalAPERFrom(v *RequestType, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestTypeMethodUnmarshalAPERLegacy(v *RequestType, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRequestTypeMethodUnmarshalAPERWithOptions(v *RequestType, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRequestTypeValueCodecFieldCapture(v *RequestTypeValueCodec) *func(RequestType, aper.DecodeState) (RequestType, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestTypeValueCodecFieldCompare(v *RequestTypeValueCodec) *func(RequestType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRequestTypeValueCodecFieldContext(v *RequestTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestTypeValueCodecFieldDecode(v *RequestTypeValueCodec) *func([]byte, aper.DecodeState) (RequestType, error) {
	return &v.decode
}
func BridgeRequestTypeValueCodecFieldEncode(v *RequestTypeValueCodec) *func(RequestType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestTypeValueCodecFieldPath(v *RequestTypeValueCodec) *aper.Path { return &v.path }
func BridgeRequestTypeValueCodecMethodEncodeBudgetValue(v RequestTypeValueCodec, a0 RequestType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRequestTypeValueCodecMethodEncodeChanged(v RequestTypeValueCodec, a0 RequestType, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRequestedTNLInfoAPERValueFieldContext(v *RequestedTNLInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedTNLInfoAPERValueFieldReceived(v *RequestedTNLInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRequestedTNLInfoAPERValueFieldReplay(v *RequestedTNLInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRequestedTNLInfoAPERValueFieldWithoutReplay(v *RequestedTNLInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRequestedTNLInfoFieldExtCount(v *RequestedTNLInfo) *int64   { return &v.extCount }
func BridgeRequestedTNLInfoFieldExtData(v *RequestedTNLInfo) *[][]byte { return &v.extData }
func BridgeRequestedTNLInfoFieldExtOrigin(v *RequestedTNLInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRequestedTNLInfoFieldExtPresent(v *RequestedTNLInfo) *[]bool       { return &v.extPresent }
func BridgeRequestedTNLInfoFieldExtWire(v *RequestedTNLInfo) *[]aper.WireSpan { return &v.extWire }
func BridgeRequestedTNLInfoFieldIEExtensionsIndef(v *RequestedTNLInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeRequestedTNLInfoFieldPerExtPadding(v *RequestedTNLInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRequestedTNLInfoFieldPerPadding(v *RequestedTNLInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRequestedTNLInfoFieldReceived(v *RequestedTNLInfo) *bool { return &v.received }
func BridgeRequestedTNLInfoFieldReceivedAbsolute(v *RequestedTNLInfo) *bool {
	return &v.receivedAbsolute
}
func BridgeRequestedTNLInfoFieldReceivedBytes(v *RequestedTNLInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRequestedTNLInfoFieldReceivedLocation(v *RequestedTNLInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeRequestedTNLInfoFieldReplay(v *RequestedTNLInfo) *aper.Snapshot { return &v.replay }
func BridgeRequestedTNLInfoFieldStream(v *RequestedTNLInfo) *aper.WireSpan { return &v.stream }
func BridgeRequestedTNLInfoFieldWithoutReplay(v *RequestedTNLInfo) *bool   { return &v.withoutReplay }
func BridgeRequestedTNLInfoMethodMarshalAPERBudget(v *RequestedTNLInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRequestedTNLInfoMethodMarshalAPERBudgetValue(v *RequestedTNLInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRequestedTNLInfoMethodMarshalAPERChanged(v *RequestedTNLInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRequestedTNLInfoMethodMarshalAPERChangedValue(v *RequestedTNLInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRequestedTNLInfoMethodMarshalAPERLegacy(v *RequestedTNLInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRequestedTNLInfoMethodMarshalAPERNewValue(v *RequestedTNLInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRequestedTNLInfoMethodMarshalAPERPlanned(v *RequestedTNLInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRequestedTNLInfoMethodMarshalAPERTo(v *RequestedTNLInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRequestedTNLInfoMethodUnmarshalAPERFrom(v *RequestedTNLInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestedTNLInfoMethodUnmarshalAPERLegacy(v *RequestedTNLInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRequestedTNLInfoMethodUnmarshalAPERWithOptions(v *RequestedTNLInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRequestedTNLInfoValueCodecFieldCapture(v *RequestedTNLInfoValueCodec) *func(RequestedTNLInfo, aper.DecodeState) (RequestedTNLInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestedTNLInfoValueCodecFieldCompare(v *RequestedTNLInfoValueCodec) *func(RequestedTNLInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRequestedTNLInfoValueCodecFieldContext(v *RequestedTNLInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedTNLInfoValueCodecFieldDecode(v *RequestedTNLInfoValueCodec) *func([]byte, aper.DecodeState) (RequestedTNLInfo, error) {
	return &v.decode
}
func BridgeRequestedTNLInfoValueCodecFieldEncode(v *RequestedTNLInfoValueCodec) *func(RequestedTNLInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestedTNLInfoValueCodecFieldPath(v *RequestedTNLInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeRequestedTNLInfoValueCodecMethodEncodeBudgetValue(v RequestedTNLInfoValueCodec, a0 RequestedTNLInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRequestedTNLInfoValueCodecMethodEncodeChanged(v RequestedTNLInfoValueCodec, a0 RequestedTNLInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *LocationReportingControlIEValue) Selected() (any, bool) {
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
	case 98:
		if value, ok := v.AsRequestType(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *RecommendedCellItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 214:
		if value, ok := v.AsRecommendedCellItem(); ok {
			return value, true
		}
	}
	return nil, false
}
