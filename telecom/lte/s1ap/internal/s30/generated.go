// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s30 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s30

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
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
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainer(v *s22.LocationReportingFailureIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainer(v *s22.LocationReportingFailureIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *s26.MMEConfigurationUpdateAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(v *s26.MMEConfigurationUpdateAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(v *s27.MMEConfigurationUpdateFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(v *s27.MMEConfigurationUpdateFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainer(v *s25.MMEStatusTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainer(v *s25.MMEStatusTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(v *s22.NASNonDeliveryIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainer(v *s22.NASNonDeliveryIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainer(v *s27.PathSwitchRequestFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainer(v *s27.PathSwitchRequestFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePrivateMessageIEsValueCaptureS1APPrivateIEContainer(v *s29.PrivateMessageIEsValuePrivateIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePrivateMessageIEsValueCompareS1APPrivateIEContainer(v *s29.PrivateMessageIEsValuePrivateIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.RecommendedCellsForPagingItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.RecommendedCellsForPagingItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.RecommendedCellsForPagingExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.RecommendedCellsForPagingExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// RecommendedCellItemIEContainer is ProtocolIE-Container {{RecommendedCellItemIEs}} of TS 36.413: a list of RecommendedCellItemIEField values.
type RecommendedCellItemIEContainer []RecommendedCellItemIEField

// InitialContextSetupFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{InitialContextSetupFailureIEs}} codec of TS 36.413.
func InitialContextSetupFailureIEValueERABIEContainerListCodec(table s00.InitialContextSetupFailureIEValueIETable) s26.InitialContextSetupFailureIEValueERABIEContainerListValueCodec {
	codec := InitialContextSetupFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.InitialContextSetupFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.InitialContextSetupFailureIEValueERABIEContainerListValueCodec {
		sealed := s26.InitialContextSetupFailureIEValueERABIEContainerListValueCodec{}
		*s26.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "InitialContextSetupFailureIEValueERABIEContainerList"
		*s26.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.InitialContextSetupFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.InitialContextSetupFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.InitialContextSetupFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.InitialContextSetupFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(&codec))(s26.InitialContextSetupFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.InitialContextSetupFailureIEValueERABIEContainerList, options aper.DecodeState) (s26.InitialContextSetupFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeInitialContextSetupFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.InitialContextSetupFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{LocationReportingFailureIndicationIEs}} codec of TS 36.413.
func LocationReportingFailureIndicationIEValueERABIEContainerListCodec(table s00.LocationReportingFailureIndicationIEValueIETable) s22.LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec {
	codec := LocationReportingFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s22.LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec {
		sealed := s22.LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec{}
		*s22.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "LocationReportingFailureIndicationIEValueERABIEContainerList"
		*s22.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.LocationReportingFailureIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.LocationReportingFailureIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportingFailureIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.LocationReportingFailureIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s22.LocationReportingFailureIndicationIEContainer(value), fresh, budget)
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.LocationReportingFailureIndicationIEValueERABIEContainerList, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.LocationReportingFailureIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MDTMode-ExtensionIE}} codec of TS 36.413.
func MDTModeExtensionIEIEValueERABIEContainerListCodec(table s00.MDTModeExtensionIEIEValueIETable) s28.MDTModeExtensionIEIEValueERABIEContainerListValueCodec {
	codec := MDTModeExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.MDTModeExtensionIEIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s28.MDTModeExtensionIEIEValueERABIEContainerListValueCodec {
		sealed := s28.MDTModeExtensionIEIEValueERABIEContainerListValueCodec{}
		*s28.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "MDTModeExtensionIEIEValueERABIEContainerList"
		*s28.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.MDTModeExtensionIEIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.MDTModeExtensionIEIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.MDTModeExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MDTModeExtensionIEIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s28.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.MDTModeExtensionIEIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(&codec))(s28.MDTModeExtensionIEIEContainer(value), fresh, budget)
		}
		*s28.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.MDTModeExtensionIEIEValueERABIEContainerList, options aper.DecodeState) (s28.MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s28.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.MDTModeExtensionIEIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable) s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := MMEConfigurationUpdateAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec {
		sealed := s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec{}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList"
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.MMEConfigurationUpdateAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.MMEConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueERABIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable) s27.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
		sealed := s27.MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateFailureIEValueERABIEContainerList"
		*s27.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.MMEConfigurationUpdateFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.MMEConfigurationUpdateFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.MMEConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.MMEConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s27.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.MMEConfigurationUpdateFailureIEValueERABIEContainerList, options aper.DecodeState) (s27.MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.MMEConfigurationUpdateFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEStatusTransferIEs}} codec of TS 36.413.
func MMEStatusTransferIEValueERABIEContainerListCodec(table s00.MMEStatusTransferIEValueIETable) s25.MMEStatusTransferIEValueERABIEContainerListValueCodec {
	codec := MMEStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s25.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s25.MMEStatusTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s25.MMEStatusTransferIEValueERABIEContainerListValueCodec {
		sealed := s25.MMEStatusTransferIEValueERABIEContainerListValueCodec{}
		*s25.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "MMEStatusTransferIEValueERABIEContainerList"
		*s25.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.MMEStatusTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.MMEStatusTransferIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.MMEStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s25.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s25.MMEStatusTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&codec))(s25.MMEStatusTransferIEContainer(value), fresh, budget)
		}
		*s25.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s25.MMEStatusTransferIEValueERABIEContainerList, options aper.DecodeState) (s25.MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s25.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s25.MMEStatusTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{NASNonDeliveryIndication-IEs}} codec of TS 36.413.
func NASNonDeliveryIndicationIEValueERABIEContainerListCodec(table s00.NASNonDeliveryIndicationIEValueIETable) s23.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec {
	codec := NASNonDeliveryIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec {
		sealed := s23.NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec{}
		*s23.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "NASNonDeliveryIndicationIEValueERABIEContainerList"
		*s23.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NASNonDeliveryIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.NASNonDeliveryIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.NASNonDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s23.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.NASNonDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s22.NASNonDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.NASNonDeliveryIndicationIEValueERABIEContainerList, options aper.DecodeState) (s23.NASNonDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.NASNonDeliveryIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PathSwitchRequestFailureIEs}} codec of TS 36.413.
func PathSwitchRequestFailureIEValueERABIEContainerListCodec(table s00.PathSwitchRequestFailureIEValueIETable) s27.PathSwitchRequestFailureIEValueERABIEContainerListValueCodec {
	codec := PathSwitchRequestFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.PathSwitchRequestFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.PathSwitchRequestFailureIEValueERABIEContainerListValueCodec {
		sealed := s27.PathSwitchRequestFailureIEValueERABIEContainerListValueCodec{}
		*s27.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "PathSwitchRequestFailureIEValueERABIEContainerList"
		*s27.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.PathSwitchRequestFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.PathSwitchRequestFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.PathSwitchRequestFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.PathSwitchRequestFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(&codec))(s27.PathSwitchRequestFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.PathSwitchRequestFailureIEValueERABIEContainerList, options aper.DecodeState) (s27.PathSwitchRequestFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.PathSwitchRequestFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellsForPagingExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RecommendedCellsForPaging-ExtIEs}} codec of TS 36.413.
func RecommendedCellsForPagingExtIEsValueExtensionFieldTableCodec(table s00.RecommendedCellsForPagingExtIEsValueExtensionTable) s12.RecommendedCellsForPagingExtIEsExtFieldValueCodec {
	if !*s00.BridgeRecommendedCellsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RecommendedCellsForPagingExtIEsExtFieldValueCodec{}
	}
	return func() s12.RecommendedCellsForPagingExtIEsExtFieldValueCodec {
		sealed := s12.RecommendedCellsForPagingExtIEsExtFieldValueCodec{}
		*s12.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldPath(&sealed) = "RecommendedCellsForPagingExtIEsExtField"
		*s12.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RecommendedCellsForPagingExtIEsExtField, error) {
			var field s12.RecommendedCellsForPagingExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedCellsForPagingExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedCellsForPagingExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedCellsForPagingExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.RecommendedCellsForPagingExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.RecommendedCellsForPagingExtIEsExtField, options aper.DecodeState) (s12.RecommendedCellsForPagingExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.RecommendedCellsForPagingExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellsForPagingItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RecommendedCellsForPagingItem-ExtIEs}} codec of TS 36.413.
func RecommendedCellsForPagingItemExtIEsValueExtensionFieldTableCodec(table s00.RecommendedCellsForPagingItemExtIEsValueExtensionTable) s12.RecommendedCellsForPagingItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeRecommendedCellsForPagingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RecommendedCellsForPagingItemExtIEsExtFieldValueCodec{}
	}
	return func() s12.RecommendedCellsForPagingItemExtIEsExtFieldValueCodec {
		sealed := s12.RecommendedCellsForPagingItemExtIEsExtFieldValueCodec{}
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "RecommendedCellsForPagingItemExtIEsExtField"
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RecommendedCellsForPagingItemExtIEsExtField, error) {
			var field s12.RecommendedCellsForPagingItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedCellsForPagingItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedCellsForPagingItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedCellsForPagingItemExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.RecommendedCellsForPagingItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.RecommendedCellsForPagingItemExtIEsExtField, options aper.DecodeState) (s12.RecommendedCellsForPagingItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.RecommendedCellsForPagingItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellsForPagingExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RecommendedCellsForPaging-ExtIEs}} codec of TS 36.413.
func RecommendedCellsForPagingExtIEsValueExtensionTableCodec(table s00.RecommendedCellsForPagingExtIEsValueExtensionTable, bounds aper.ListBounds) s12.RecommendedCellsForPagingExtIEsExtContainerValueCodec {
	if !*s00.BridgeRecommendedCellsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RecommendedCellsForPagingExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.RecommendedCellsForPagingExtIEsExtContainerValueCodec {
		sealed := s12.RecommendedCellsForPagingExtIEsExtContainerValueCodec{}
		*s12.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldPath(&sealed) = "RecommendedCellsForPagingExtIEsExtContainer"
		*s12.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RecommendedCellsForPagingExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.RecommendedCellsForPagingExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.RecommendedCellsForPagingExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s12.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.RecommendedCellsForPagingExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.RecommendedCellsForPagingExtIEsExtContainer, options aper.DecodeState) (s12.RecommendedCellsForPagingExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.RecommendedCellsForPagingExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RecommendedCellsForPagingItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RecommendedCellsForPagingItem-ExtIEs}} codec of TS 36.413.
func RecommendedCellsForPagingItemExtIEsValueExtensionTableCodec(table s00.RecommendedCellsForPagingItemExtIEsValueExtensionTable, bounds aper.ListBounds) s12.RecommendedCellsForPagingItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeRecommendedCellsForPagingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RecommendedCellsForPagingItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.RecommendedCellsForPagingItemExtIEsExtContainerValueCodec {
		sealed := s12.RecommendedCellsForPagingItemExtIEsExtContainerValueCodec{}
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "RecommendedCellsForPagingItemExtIEsExtContainer"
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RecommendedCellsForPagingItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.RecommendedCellsForPagingItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.RecommendedCellsForPagingItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.RecommendedCellsForPagingItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.RecommendedCellsForPagingItemExtIEsExtContainer, options aper.DecodeState) (s12.RecommendedCellsForPagingItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.RecommendedCellsForPagingItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{LocationReportingFailureIndicationIEs}} codec of TS 36.413.
func LocationReportingFailureIndicationIEValueIEFieldTableCodec(table s00.LocationReportingFailureIndicationIEValueIETable) s22.LocationReportingFailureIndicationIEFieldValueCodec {
	if !*s00.BridgeLocationReportingFailureIndicationIEValueIETableFieldBound(&table) {
		return s22.LocationReportingFailureIndicationIEFieldValueCodec{}
	}
	return func() s22.LocationReportingFailureIndicationIEFieldValueCodec {
		sealed := s22.LocationReportingFailureIndicationIEFieldValueCodec{}
		*s22.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldPath(&sealed) = "LocationReportingFailureIndicationIEField"
		*s22.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEField, error) {
			var field s22.LocationReportingFailureIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportingFailureIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEField")
			}
			return field, nil
		}
		*s22.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s22.LocationReportingFailureIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s22.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s22.LocationReportingFailureIndicationIEField, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s22.LocationReportingFailureIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MDTMode-ExtensionIE}} codec of TS 36.413.
func MDTModeExtensionIEIEValueIEFieldTableCodec(table s00.MDTModeExtensionIEIEValueIETable) s28.MDTModeExtensionIEIEFieldValueCodec {
	if !*s00.BridgeMDTModeExtensionIEIEValueIETableFieldBound(&table) {
		return s28.MDTModeExtensionIEIEFieldValueCodec{}
	}
	return func() s28.MDTModeExtensionIEIEFieldValueCodec {
		sealed := s28.MDTModeExtensionIEIEFieldValueCodec{}
		*s28.BridgeMDTModeExtensionIEIEFieldValueCodecFieldPath(&sealed) = "MDTModeExtensionIEIEField"
		*s28.BridgeMDTModeExtensionIEIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.MDTModeExtensionIEIEField, error) {
			var field s28.MDTModeExtensionIEIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s28.BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MDTModeExtensionIEIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEField")
			}
			return field, nil
		}
		*s28.BridgeMDTModeExtensionIEIEFieldValueCodecFieldEncode(&sealed) = func(field s28.MDTModeExtensionIEIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s28.BridgeMDTModeExtensionIEIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s28.BridgeMDTModeExtensionIEIEFieldValueCodecFieldCapture(&sealed) = func(v s28.MDTModeExtensionIEIEField, options aper.DecodeState) (s28.MDTModeExtensionIEIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeMDTModeExtensionIEIEFieldValueCodecFieldCompare(&sealed) = func(v s28.MDTModeExtensionIEIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeMDTModeExtensionIEIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func MMEConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable) s26.MMEConfigurationUpdateAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&table) {
		return s26.MMEConfigurationUpdateAcknowledgeIEFieldValueCodec{}
	}
	return func() s26.MMEConfigurationUpdateAcknowledgeIEFieldValueCodec {
		sealed := s26.MMEConfigurationUpdateAcknowledgeIEFieldValueCodec{}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateAcknowledgeIEField"
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEField, error) {
			var field s26.MMEConfigurationUpdateAcknowledgeIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateAcknowledgeIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEField")
			}
			return field, nil
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldEncode(&sealed) = func(field s26.MMEConfigurationUpdateAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCapture(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEField, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCompare(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueIEFieldTableCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable) s27.MMEConfigurationUpdateFailureIEFieldValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateFailureIEValueIETableFieldBound(&table) {
		return s27.MMEConfigurationUpdateFailureIEFieldValueCodec{}
	}
	return func() s27.MMEConfigurationUpdateFailureIEFieldValueCodec {
		sealed := s27.MMEConfigurationUpdateFailureIEFieldValueCodec{}
		*s27.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateFailureIEField"
		*s27.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.MMEConfigurationUpdateFailureIEField, error) {
			var field s26.MMEConfigurationUpdateFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailureIEField")
			}
			return field, nil
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s26.MMEConfigurationUpdateFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s26.MMEConfigurationUpdateFailureIEField, options aper.DecodeState) (s26.MMEConfigurationUpdateFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s26.MMEConfigurationUpdateFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEStatusTransferIEs}} codec of TS 36.413.
func MMEStatusTransferIEValueIEFieldTableCodec(table s00.MMEStatusTransferIEValueIETable) s25.MMEStatusTransferIEFieldValueCodec {
	if !*s00.BridgeMMEStatusTransferIEValueIETableFieldBound(&table) {
		return s25.MMEStatusTransferIEFieldValueCodec{}
	}
	return func() s25.MMEStatusTransferIEFieldValueCodec {
		sealed := s25.MMEStatusTransferIEFieldValueCodec{}
		*s25.BridgeMMEStatusTransferIEFieldValueCodecFieldPath(&sealed) = "MMEStatusTransferIEField"
		*s25.BridgeMMEStatusTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.MMEStatusTransferIEField, error) {
			var field s25.MMEStatusTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s25.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEStatusTransferIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEStatusTransferIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEStatusTransferIEField")
			}
			return field, nil
		}
		*s25.BridgeMMEStatusTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s25.MMEStatusTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s25.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s25.BridgeMMEStatusTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s25.MMEStatusTransferIEField, options aper.DecodeState) (s25.MMEStatusTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s25.BridgeMMEStatusTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s25.MMEStatusTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeMMEStatusTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{NASNonDeliveryIndication-IEs}} codec of TS 36.413.
func NASNonDeliveryIndicationIEValueIEFieldTableCodec(table s00.NASNonDeliveryIndicationIEValueIETable) s23.NASNonDeliveryIndicationIEFieldValueCodec {
	if !*s00.BridgeNASNonDeliveryIndicationIEValueIETableFieldBound(&table) {
		return s23.NASNonDeliveryIndicationIEFieldValueCodec{}
	}
	return func() s23.NASNonDeliveryIndicationIEFieldValueCodec {
		sealed := s23.NASNonDeliveryIndicationIEFieldValueCodec{}
		*s23.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldPath(&sealed) = "NASNonDeliveryIndicationIEField"
		*s23.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.NASNonDeliveryIndicationIEField, error) {
			var field s22.NASNonDeliveryIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASNonDeliveryIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NASNonDeliveryIndicationIEField")
			}
			return field, nil
		}
		*s23.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s22.NASNonDeliveryIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s22.NASNonDeliveryIndicationIEField, options aper.DecodeState) (s22.NASNonDeliveryIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s22.NASNonDeliveryIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PathSwitchRequestFailureIEs}} codec of TS 36.413.
func PathSwitchRequestFailureIEValueIEFieldTableCodec(table s00.PathSwitchRequestFailureIEValueIETable) s27.PathSwitchRequestFailureIEFieldValueCodec {
	if !*s00.BridgePathSwitchRequestFailureIEValueIETableFieldBound(&table) {
		return s27.PathSwitchRequestFailureIEFieldValueCodec{}
	}
	return func() s27.PathSwitchRequestFailureIEFieldValueCodec {
		sealed := s27.PathSwitchRequestFailureIEFieldValueCodec{}
		*s27.BridgePathSwitchRequestFailureIEFieldValueCodecFieldPath(&sealed) = "PathSwitchRequestFailureIEField"
		*s27.BridgePathSwitchRequestFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.PathSwitchRequestFailureIEField, error) {
			var field s27.PathSwitchRequestFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s27.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PathSwitchRequestFailureIEField")
			}
			return field, nil
		}
		*s27.BridgePathSwitchRequestFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s27.PathSwitchRequestFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s27.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s27.BridgePathSwitchRequestFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s27.PathSwitchRequestFailureIEField, options aper.DecodeState) (s27.PathSwitchRequestFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgePathSwitchRequestFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s27.PathSwitchRequestFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgePathSwitchRequestFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return RecommendedCellItemIEFieldValueCodec{path: "RecommendedCellItemIEField", decode: func(data []byte, options aper.DecodeState) (RecommendedCellItemIEField, error) {
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

// InitialContextSetupFailureIEValueIETableCodec constructs the ProtocolIE-Container {{InitialContextSetupFailureIEs}} codec of TS 36.413.
func InitialContextSetupFailureIEValueIETableCodec(table s00.InitialContextSetupFailureIEValueIETable, bounds aper.ListBounds) s26.InitialContextSetupFailureIEContainerValueCodec {
	if !*s00.BridgeInitialContextSetupFailureIEValueIETableFieldBound(&table) {
		return s26.InitialContextSetupFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s26.InitialContextSetupFailureIEContainerValueCodec {
		sealed := s26.InitialContextSetupFailureIEContainerValueCodec{}
		*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldPath(&sealed) = "InitialContextSetupFailureIEContainer"
		*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.InitialContextSetupFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.InitialContextSetupFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.InitialContextSetupFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupFailureIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEContainer")
			}
			return fields, nil
		}
		*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s26.InitialContextSetupFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s26.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s26.InitialContextSetupFailureIEContainer, options aper.DecodeState) (s26.InitialContextSetupFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s26.InitialContextSetupFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s29.BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{LocationReportingFailureIndicationIEs}} codec of TS 36.413.
func LocationReportingFailureIndicationIEValueIETableCodec(table s00.LocationReportingFailureIndicationIEValueIETable, bounds aper.ListBounds) s22.LocationReportingFailureIndicationIEContainerValueCodec {
	if !*s00.BridgeLocationReportingFailureIndicationIEValueIETableFieldBound(&table) {
		return s22.LocationReportingFailureIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.LocationReportingFailureIndicationIEContainerValueCodec {
		sealed := s22.LocationReportingFailureIndicationIEContainerValueCodec{}
		*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldPath(&sealed) = "LocationReportingFailureIndicationIEContainer"
		*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.LocationReportingFailureIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.LocationReportingFailureIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportingFailureIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEContainer")
			}
			return fields, nil
		}
		*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.LocationReportingFailureIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s22.LocationReportingFailureIndicationIEContainer, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s22.LocationReportingFailureIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueIETableCodec constructs the ProtocolIE-Container {{MDTMode-ExtensionIE}} codec of TS 36.413.
func MDTModeExtensionIEIEValueIETableCodec(table s00.MDTModeExtensionIEIEValueIETable, bounds aper.ListBounds) s28.MDTModeExtensionIEIEContainerValueCodec {
	if !*s00.BridgeMDTModeExtensionIEIEValueIETableFieldBound(&table) {
		return s28.MDTModeExtensionIEIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s28.MDTModeExtensionIEIEContainerValueCodec {
		sealed := s28.MDTModeExtensionIEIEContainerValueCodec{}
		*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldPath(&sealed) = "MDTModeExtensionIEIEContainer"
		*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.MDTModeExtensionIEIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.MDTModeExtensionIEIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.MDTModeExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MDTModeExtensionIEIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEContainer")
			}
			return fields, nil
		}
		*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(&sealed) = func(fields s28.MDTModeExtensionIEIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s28.BridgeMDTModeExtensionIEIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldCapture(&sealed) = func(v s28.MDTModeExtensionIEIEContainer, options aper.DecodeState) (s28.MDTModeExtensionIEIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldCompare(&sealed) = func(v s28.MDTModeExtensionIEIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{MMEConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func MMEConfigurationUpdateAcknowledgeIEValueIETableCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable, bounds aper.ListBounds) s26.MMEConfigurationUpdateAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&table) {
		return s26.MMEConfigurationUpdateAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s26.MMEConfigurationUpdateAcknowledgeIEContainerValueCodec {
		sealed := s26.MMEConfigurationUpdateAcknowledgeIEContainerValueCodec{}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateAcknowledgeIEContainer"
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.MMEConfigurationUpdateAcknowledgeIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.MMEConfigurationUpdateAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateAcknowledgeIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEContainer")
			}
			return fields, nil
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&sealed) = func(fields s26.MMEConfigurationUpdateAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCapture(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEContainer, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCompare(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueIETableCodec constructs the ProtocolIE-Container {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueIETableCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s27.MMEConfigurationUpdateFailureIEContainerValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateFailureIEValueIETableFieldBound(&table) {
		return s27.MMEConfigurationUpdateFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s27.MMEConfigurationUpdateFailureIEContainerValueCodec {
		sealed := s27.MMEConfigurationUpdateFailureIEContainerValueCodec{}
		*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateFailureIEContainer"
		*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.MMEConfigurationUpdateFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.MMEConfigurationUpdateFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.MMEConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s27.MMEConfigurationUpdateFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s27.MMEConfigurationUpdateFailureIEContainer, options aper.DecodeState) (s27.MMEConfigurationUpdateFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s27.MMEConfigurationUpdateFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueIETableCodec constructs the ProtocolIE-Container {{MMEStatusTransferIEs}} codec of TS 36.413.
func MMEStatusTransferIEValueIETableCodec(table s00.MMEStatusTransferIEValueIETable, bounds aper.ListBounds) s25.MMEStatusTransferIEContainerValueCodec {
	if !*s00.BridgeMMEStatusTransferIEValueIETableFieldBound(&table) {
		return s25.MMEStatusTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s25.MMEStatusTransferIEContainerValueCodec {
		sealed := s25.MMEStatusTransferIEContainerValueCodec{}
		*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldPath(&sealed) = "MMEStatusTransferIEContainer"
		*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.MMEStatusTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.MMEStatusTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.MMEStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s25.MMEStatusTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s25.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s25.MMEStatusTransferIEContainer, options aper.DecodeState) (s25.MMEStatusTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s25.MMEStatusTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{NASNonDeliveryIndication-IEs}} codec of TS 36.413.
func NASNonDeliveryIndicationIEValueIETableCodec(table s00.NASNonDeliveryIndicationIEValueIETable, bounds aper.ListBounds) s22.NASNonDeliveryIndicationIEContainerValueCodec {
	if !*s00.BridgeNASNonDeliveryIndicationIEValueIETableFieldBound(&table) {
		return s22.NASNonDeliveryIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s22.NASNonDeliveryIndicationIEContainerValueCodec {
		sealed := s22.NASNonDeliveryIndicationIEContainerValueCodec{}
		*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldPath(&sealed) = "NASNonDeliveryIndicationIEContainer"
		*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.NASNonDeliveryIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.NASNonDeliveryIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.NASNonDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s22.NASNonDeliveryIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s22.NASNonDeliveryIndicationIEContainer, options aper.DecodeState) (s22.NASNonDeliveryIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s22.NASNonDeliveryIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestFailureIEValueIETableCodec constructs the ProtocolIE-Container {{PathSwitchRequestFailureIEs}} codec of TS 36.413.
func PathSwitchRequestFailureIEValueIETableCodec(table s00.PathSwitchRequestFailureIEValueIETable, bounds aper.ListBounds) s27.PathSwitchRequestFailureIEContainerValueCodec {
	if !*s00.BridgePathSwitchRequestFailureIEValueIETableFieldBound(&table) {
		return s27.PathSwitchRequestFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s27.PathSwitchRequestFailureIEContainerValueCodec {
		sealed := s27.PathSwitchRequestFailureIEContainerValueCodec{}
		*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldPath(&sealed) = "PathSwitchRequestFailureIEContainer"
		*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.PathSwitchRequestFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.PathSwitchRequestFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.PathSwitchRequestFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s27.PathSwitchRequestFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s27.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s27.PathSwitchRequestFailureIEContainer, options aper.DecodeState) (s27.PathSwitchRequestFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s27.PathSwitchRequestFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return RecommendedCellItemIEContainerValueCodec{path: "RecommendedCellItemIEContainer", decode: func(data []byte, options aper.DecodeState) (RecommendedCellItemIEContainer, error) {
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
func PrivateMessageIEsValuePrivateFieldTableCodec(table s00.PrivateMessageIEsValuePrivateTable) s29.PrivateMessageIEsValuePrivateIEFieldValueCodec {
	if !*s00.BridgePrivateMessageIEsValuePrivateTableFieldBound(&table) {
		return s29.PrivateMessageIEsValuePrivateIEFieldValueCodec{}
	}
	return func() s29.PrivateMessageIEsValuePrivateIEFieldValueCodec {
		sealed := s29.PrivateMessageIEsValuePrivateIEFieldValueCodec{}
		*s29.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldPath(&sealed) = "PrivateMessageIEsValuePrivateIEField"
		*s29.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.PrivateMessageIEsValuePrivateIEField, error) {
			var field s29.PrivateMessageIEsValuePrivateIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s29.BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PrivateMessageIEsValuePrivateIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PrivateMessageIEsValuePrivateIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PrivateMessageIEsValuePrivateIEField")
			}
			return field, nil
		}
		*s29.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldEncode(&sealed) = func(field s29.PrivateMessageIEsValuePrivateIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s29.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s29.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldCapture(&sealed) = func(v s29.PrivateMessageIEsValuePrivateIEField, options aper.DecodeState) (s29.PrivateMessageIEsValuePrivateIEField, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePrivateMessageIEsValueCaptureS1APPrivateIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s29.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldCompare(&sealed) = func(v s29.PrivateMessageIEsValuePrivateIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePrivateMessageIEsValueCompareS1APPrivateIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgePrivateMessageIEsValuePrivateIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PrivateMessageIEsValuePrivateTableCodec constructs the PrivateIE-Container {{PrivateMessageIEs}} codec of TS 36.413.
func PrivateMessageIEsValuePrivateTableCodec(table s00.PrivateMessageIEsValuePrivateTable, bounds aper.ListBounds) s29.PrivateMessageIEsValuePrivateIEContainerValueCodec {
	if !*s00.BridgePrivateMessageIEsValuePrivateTableFieldBound(&table) {
		return s29.PrivateMessageIEsValuePrivateIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s29.PrivateMessageIEsValuePrivateIEContainerValueCodec {
		sealed := s29.PrivateMessageIEsValuePrivateIEContainerValueCodec{}
		*s29.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldPath(&sealed) = "PrivateMessageIEsValuePrivateIEContainer"
		*s29.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.PrivateMessageIEsValuePrivateIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s29.PrivateMessageIEsValuePrivateIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s29.PrivateMessageIEsValuePrivateIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s29.BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s29.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldEncode(&sealed) = func(fields s29.PrivateMessageIEsValuePrivateIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s29.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s29.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldCapture(&sealed) = func(v s29.PrivateMessageIEsValuePrivateIEContainer, options aper.DecodeState) (s29.PrivateMessageIEsValuePrivateIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePrivateMessageIEsValueCaptureS1APPrivateIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*s29.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldCompare(&sealed) = func(v s29.PrivateMessageIEsValuePrivateIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePrivateMessageIEsValueCompareS1APPrivateIEContainer(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgePrivateMessageIEsValuePrivateIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{InitialContextSetupFailureIEs}} codec of TS 36.413.
func InitialContextSetupFailureIEValueProtocolErrorIEContainerListCodec(table s00.InitialContextSetupFailureIEValueIETable) s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := InitialContextSetupFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "InitialContextSetupFailureIEValueProtocolErrorIEContainerList"
		*s26.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.InitialContextSetupFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupFailureIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(&codec))(s26.InitialContextSetupFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{LocationReportingFailureIndicationIEs}} codec of TS 36.413.
func LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListCodec(table s00.LocationReportingFailureIndicationIEValueIETable) s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := LocationReportingFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList"
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.LocationReportingFailureIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s22.LocationReportingFailureIndicationIEContainer(value), fresh, budget)
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MDTMode-ExtensionIE}} codec of TS 36.413.
func MDTModeExtensionIEIEValueProtocolErrorIEContainerListCodec(table s00.MDTModeExtensionIEIEValueIETable) s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
	codec := MDTModeExtensionIEIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec{}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "MDTModeExtensionIEIEValueProtocolErrorIEContainerList"
		*s28.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.MDTModeExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MDTModeExtensionIEIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(&codec))(s28.MDTModeExtensionIEIEContainer(value), fresh, budget)
		}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable) s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEConfigurationUpdateAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList"
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.MMEConfigurationUpdateAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.MMEConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEConfigurationUpdateFailureIEs}} codec of TS 36.413.
func MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable) s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList"
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.MMEConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s27.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEStatusTransferIEs}} codec of TS 36.413.
func MMEStatusTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEStatusTransferIEValueIETable) s25.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s25.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s25.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s25.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s25.MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s25.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "MMEStatusTransferIEValueProtocolErrorIEContainerList"
		*s25.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.MMEStatusTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.MMEStatusTransferIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.MMEStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s25.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s25.MMEStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&codec))(s25.MMEStatusTransferIEContainer(value), fresh, budget)
		}
		*s25.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s25.MMEStatusTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s25.MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s25.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s25.MMEStatusTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{NASNonDeliveryIndication-IEs}} codec of TS 36.413.
func NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListCodec(table s00.NASNonDeliveryIndicationIEValueIETable) s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := NASNonDeliveryIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList"
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.NASNonDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s22.NASNonDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PathSwitchRequestFailureIEs}} codec of TS 36.413.
func PathSwitchRequestFailureIEValueProtocolErrorIEContainerListCodec(table s00.PathSwitchRequestFailureIEValueIETable) s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := PathSwitchRequestFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s27.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "PathSwitchRequestFailureIEValueProtocolErrorIEContainerList"
		*s27.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.PathSwitchRequestFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(&codec))(s27.PathSwitchRequestFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {InitialContextSetupFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func InitialContextSetupFailureIEValueProtocolIEContainerListCodec(table s00.InitialContextSetupFailureIEValueIETable, bounds aper.ListBounds) s26.InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec {
	codec := InitialContextSetupFailureIEValueIETableCodec(table, bounds)
	if *s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s26.InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s26.InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec{}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "InitialContextSetupFailureIEValueProtocolIEContainerList"
		*s26.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.InitialContextSetupFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.InitialContextSetupFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.InitialContextSetupFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupFailureIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InitialContextSetupFailureIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.InitialContextSetupFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(&codec))(s26.InitialContextSetupFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.InitialContextSetupFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s26.InitialContextSetupFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.InitialContextSetupFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LocationReportingFailureIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {LocationReportingFailureIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func LocationReportingFailureIndicationIEValueProtocolIEContainerListCodec(table s00.LocationReportingFailureIndicationIEValueIETable, bounds aper.ListBounds) s22.LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec {
	codec := LocationReportingFailureIndicationIEValueIETableCodec(table, bounds)
	if *s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s22.LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s22.LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s22.LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec{}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "LocationReportingFailureIndicationIEValueProtocolIEContainerList"
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s22.LocationReportingFailureIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.LocationReportingFailureIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportingFailureIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LocationReportingFailureIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s22.LocationReportingFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s22.LocationReportingFailureIndicationIEContainer(value), fresh, budget)
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s22.LocationReportingFailureIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s22.LocationReportingFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s22.LocationReportingFailureIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MDTModeExtensionIEIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MDTMode-ExtensionIE} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MDTModeExtensionIEIEValueProtocolIEContainerListCodec(table s00.MDTModeExtensionIEIEValueIETable, bounds aper.ListBounds) s28.MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec {
	codec := MDTModeExtensionIEIEValueIETableCodec(table, bounds)
	if *s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s28.MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec {
		sealed := s28.MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec{}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "MDTModeExtensionIEIEValueProtocolIEContainerList"
		*s28.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.MDTModeExtensionIEIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.MDTModeExtensionIEIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.MDTModeExtensionIEIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MDTModeExtensionIEIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MDTModeExtensionIEIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.MDTModeExtensionIEIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(&codec))(s28.MDTModeExtensionIEIEContainer(value), fresh, budget)
		}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.MDTModeExtensionIEIEValueProtocolIEContainerList, options aper.DecodeState) (s28.MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.MDTModeExtensionIEIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationUpdateAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationUpdateAcknowledgeIEValueIETable, bounds aper.ListBounds) s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := MMEConfigurationUpdateAcknowledgeIEValueIETableCodec(table, bounds)
	if *s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec {
		sealed := s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec{}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList"
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.MMEConfigurationUpdateAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.MMEConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationUpdateFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationUpdateFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEConfigurationUpdateFailureIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
	codec := MMEConfigurationUpdateFailureIEValueIETableCodec(table, bounds)
	if *s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationUpdateFailureIEValueProtocolIEContainerList"
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.MMEConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s27.MMEConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEStatusTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEStatusTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEStatusTransferIEValueProtocolIEContainerListCodec(table s00.MMEStatusTransferIEValueIETable, bounds aper.ListBounds) s25.MMEStatusTransferIEValueProtocolIEContainerListValueCodec {
	codec := MMEStatusTransferIEValueIETableCodec(table, bounds)
	if *s25.BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s25.MMEStatusTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s25.MMEStatusTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s25.MMEStatusTransferIEValueProtocolIEContainerListValueCodec{}
		*s25.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "MMEStatusTransferIEValueProtocolIEContainerList"
		*s25.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.MMEStatusTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.MMEStatusTransferIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.MMEStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s25.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s25.MMEStatusTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s25.BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(&codec))(s25.MMEStatusTransferIEContainer(value), fresh, budget)
		}
		*s25.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s25.MMEStatusTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s25.MMEStatusTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s25.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s25.MMEStatusTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NASNonDeliveryIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {NASNonDeliveryIndication-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func NASNonDeliveryIndicationIEValueProtocolIEContainerListCodec(table s00.NASNonDeliveryIndicationIEValueIETable, bounds aper.ListBounds) s23.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
	codec := NASNonDeliveryIndicationIEValueIETableCodec(table, bounds)
	if *s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s23.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s23.NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "NASNonDeliveryIndicationIEValueProtocolIEContainerList"
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NASNonDeliveryIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.NASNonDeliveryIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s22.NASNonDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.NASNonDeliveryIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s22.BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s22.NASNonDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.NASNonDeliveryIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s23.NASNonDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.NASNonDeliveryIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PathSwitchRequestFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PathSwitchRequestFailureIEValueProtocolIEContainerListCodec(table s00.PathSwitchRequestFailureIEValueIETable, bounds aper.ListBounds) s27.PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec {
	codec := PathSwitchRequestFailureIEValueIETableCodec(table, bounds)
	if *s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s27.PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s27.PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec{}
		*s27.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "PathSwitchRequestFailureIEValueProtocolIEContainerList"
		*s27.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.PathSwitchRequestFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.PathSwitchRequestFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.PathSwitchRequestFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.PathSwitchRequestFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(&codec))(s27.PathSwitchRequestFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.PathSwitchRequestFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s27.PathSwitchRequestFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s27.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.PathSwitchRequestFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// initialContextSetupFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[InitialContextSetupFailureIEValue].
type InitialContextSetupFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s26.InitialContextSetupFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s26.InitialContextSetupFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// locationReportingFailureIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.LocationReportingFailureIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.LocationReportingFailureIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEField(v *s22.LocationReportingFailureIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeLocationReportingFailureIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeLocationReportingFailureIndicationIEFieldFieldReplay(v), *s22.BridgeLocationReportingFailureIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEField(v *s22.LocationReportingFailureIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeLocationReportingFailureIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeLocationReportingFailureIndicationIEFieldFieldReplay(v), *s22.BridgeLocationReportingFailureIndicationIEFieldFieldWithoutReplay(v))
}

// mMEConfigurationUpdateAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s26.MMEConfigurationUpdateAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s26.MMEConfigurationUpdateAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(v *s26.MMEConfigurationUpdateAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldReplay(v), *s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v))
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(v *s26.MMEConfigurationUpdateAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldReplay(v), *s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v))
}

// mMEConfigurationUpdateFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s26.MMEConfigurationUpdateFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s26.MMEConfigurationUpdateFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(v *s26.MMEConfigurationUpdateFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s26.BridgeMMEConfigurationUpdateFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s26.BridgeMMEConfigurationUpdateFailureIEFieldFieldReplay(v), *s26.BridgeMMEConfigurationUpdateFailureIEFieldFieldWithoutReplay(v))
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v *s26.MMEConfigurationUpdateFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s26.BridgeMMEConfigurationUpdateFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s26.BridgeMMEConfigurationUpdateFailureIEFieldFieldReplay(v), *s26.BridgeMMEConfigurationUpdateFailureIEFieldFieldWithoutReplay(v))
}

// mMEStatusTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEStatusTransferIEValue].
type MMEStatusTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s25.MMEStatusTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s25.MMEStatusTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEField(v *s25.MMEStatusTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s25.BridgeMMEStatusTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s25.BridgeMMEStatusTransferIEFieldFieldReplay(v), *s25.BridgeMMEStatusTransferIEFieldFieldWithoutReplay(v))
}
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIEField(v *s25.MMEStatusTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s25.BridgeMMEStatusTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s25.BridgeMMEStatusTransferIEFieldFieldReplay(v), *s25.BridgeMMEStatusTransferIEFieldFieldWithoutReplay(v))
}

// nASNonDeliveryIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.NASNonDeliveryIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.NASNonDeliveryIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEField(v *s22.NASNonDeliveryIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s22.BridgeNASNonDeliveryIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s22.BridgeNASNonDeliveryIndicationIEFieldFieldReplay(v), *s22.BridgeNASNonDeliveryIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEField(v *s22.NASNonDeliveryIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s22.BridgeNASNonDeliveryIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s22.BridgeNASNonDeliveryIndicationIEFieldFieldReplay(v), *s22.BridgeNASNonDeliveryIndicationIEFieldFieldWithoutReplay(v))
}

// pathSwitchRequestFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s27.PathSwitchRequestFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s27.PathSwitchRequestFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEField(v *s27.PathSwitchRequestFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s27.BridgePathSwitchRequestFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s27.BridgePathSwitchRequestFailureIEFieldFieldReplay(v), *s27.BridgePathSwitchRequestFailureIEFieldFieldWithoutReplay(v))
}
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEField(v *s27.PathSwitchRequestFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s27.BridgePathSwitchRequestFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s27.BridgePathSwitchRequestFailureIEFieldFieldReplay(v), *s27.BridgePathSwitchRequestFailureIEFieldFieldWithoutReplay(v))
}

// privateMessageIEsValueProtocolPrivateValue is the concrete protocolPrivateValue[PrivateMessageIEsValue].
type PrivateMessageIEsValueProtocolPrivateValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s29.PrivateMessageIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	matchesID(s23.PrivateIEID, ...*aper.DecodeBudget) bool
	decode(s23.PrivateIEID, aper.OpaqueOpenType) (s29.PrivateMessageIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	rule() aper.SourceRule
}

func BridgePrivateMessageIEsValueCaptureS1APPrivateIEField(v *s29.PrivateMessageIEsValuePrivateIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s23.BridgeCaptureS1APPrivateIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s29.BridgePrivateMessageIEsValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s29.BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v), *s29.BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v))
}
func BridgePrivateMessageIEsValueCompareS1APPrivateIEField(v *s29.PrivateMessageIEsValuePrivateIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s23.BridgeCompareS1APPrivateIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s29.BridgePrivateMessageIEsValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s29.BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v), *s29.BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v))
}
func BridgeRecommendedCellsForPagingItemExtIEsValueCaptureS1APProtocolExtensionField(v *s12.RecommendedCellsForPagingItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldReplay(v), *s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRecommendedCellsForPagingItemExtIEsValueCompareS1APProtocolExtensionField(v *s12.RecommendedCellsForPagingItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldReplay(v), *s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldWithoutReplay(v))
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// recommendedCellsForPagingExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RecommendedCellsForPagingExtIEsValue].
type RecommendedCellsForPagingExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.RecommendedCellsForPagingExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.RecommendedCellsForPagingExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRecommendedCellsForPagingExtIEsValueCaptureS1APProtocolExtensionField(v *s12.RecommendedCellsForPagingExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeRecommendedCellsForPagingExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeRecommendedCellsForPagingExtIEsExtFieldFieldReplay(v), *s12.BridgeRecommendedCellsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRecommendedCellsForPagingExtIEsValueCompareS1APProtocolExtensionField(v *s12.RecommendedCellsForPagingExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeRecommendedCellsForPagingExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeRecommendedCellsForPagingExtIEsExtFieldFieldReplay(v), *s12.BridgeRecommendedCellsForPagingExtIEsExtFieldFieldWithoutReplay(v))
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
func BridgeInitialContextSetupFailureIEValueCompareS1APERABIEContainerList(v *s26.InitialContextSetupFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APERABIEContainerList(v *s22.LocationReportingFailureIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportingFailureIndicationIEValueCompareS1APERABIEContainerList(v *s22.LocationReportingFailureIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
	captureSemantics(aper.SemanticCapture) s28.MDTModeExtensionIEIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s28.MDTModeExtensionIEIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMDTModeExtensionIEIEValueCaptureS1APERABIEContainerList(v *s28.MDTModeExtensionIEIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMDTModeExtensionIEIEValueCompareS1APERABIEContainerList(v *s28.MDTModeExtensionIEIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APERABIEContainerList(v *s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APERABIEContainerList(v *s26.MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(v *s27.MMEConfigurationUpdateFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(v *s27.MMEConfigurationUpdateFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEStatusTransferIEValueCaptureS1APERABIEContainerList(v *s25.MMEStatusTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEStatusTransferIEValueCompareS1APERABIEContainerList(v *s25.MMEStatusTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APERABIEContainerList(v *s23.NASNonDeliveryIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASNonDeliveryIndicationIEValueCompareS1APERABIEContainerList(v *s23.NASNonDeliveryIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APERABIEContainerList(v *s27.PathSwitchRequestFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePathSwitchRequestFailureIEValueCompareS1APERABIEContainerList(v *s27.PathSwitchRequestFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEField(v *s28.MDTModeExtensionIEIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s28.BridgeMDTModeExtensionIEIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s28.BridgeMDTModeExtensionIEIEFieldFieldReplay(v), *s28.BridgeMDTModeExtensionIEIEFieldFieldWithoutReplay(v))
}
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEField(v *s28.MDTModeExtensionIEIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s28.BridgeMDTModeExtensionIEIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s28.BridgeMDTModeExtensionIEIEFieldFieldReplay(v), *s28.BridgeMDTModeExtensionIEIEFieldFieldWithoutReplay(v))
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
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEContainer(v *s28.MDTModeExtensionIEIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEContainer(v *s28.MDTModeExtensionIEIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s26.InitialContextSetupFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s22.LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolErrorIEContainerList(v *s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolErrorIEContainerList(v *s28.MDTModeExtensionIEIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s27.MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s25.MMEStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s25.MMEStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s23.NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s27.PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainerList(v *s26.InitialContextSetupFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEContainerList(v *s22.LocationReportingFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEContainerList(v *s22.LocationReportingFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEContainerList(v *s28.MDTModeExtensionIEIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEContainerList(v *s28.MDTModeExtensionIEIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(v *s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(v *s27.MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEContainerList(v *s25.MMEStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIEContainerList(v *s25.MMEStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEContainerList(v *s23.NASNonDeliveryIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(v *s23.NASNonDeliveryIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEContainerList(v *s27.PathSwitchRequestFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIEContainerList(v *s27.PathSwitchRequestFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIESingleContainer(v *s26.InitialContextSetupFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s22.LocationReportingFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingFailureIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIESingleContainer(v *s22.LocationReportingFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportingFailureIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIESingleContainer(v *s28.MDTModeExtensionIEIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMDTModeExtensionIEIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIESingleContainer(v *s28.MDTModeExtensionIEIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMDTModeExtensionIEIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *s26.MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(v *s27.MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(v *s27.MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEStatusTransferIEValueCaptureS1APProtocolIESingleContainer(v *s25.MMEStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEStatusTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEStatusTransferIEValueCompareS1APProtocolIESingleContainer(v *s25.MMEStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEStatusTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s23.NASNonDeliveryIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASNonDeliveryIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(v *s23.NASNonDeliveryIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASNonDeliveryIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIESingleContainer(v *s27.PathSwitchRequestFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePathSwitchRequestFailureIEValueCompareS1APProtocolIESingleContainer(v *s27.PathSwitchRequestFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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
func BridgeCaptureS1APInitialContextSetupFailure(v *InitialContextSetupFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeInitialContextSetupFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInitialContextSetupFailure(v *InitialContextSetupFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeInitialContextSetupFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
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
	s20.BridgeCaptureS1APEUTRANCGI(&v.EUTRANCGI, s)
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
	s20.BridgeCompareS1APEUTRANCGI(&v.EUTRANCGI, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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

// NewPrivateIEIDLocal creates a PrivateIEID with the local alternative.
func BridgeNewPrivateIEIDLocalLegacy(v int64) s23.PrivateIEID {
	return s23.PrivateIEID{
		Choice: s00.PrivateIEIDChoiceLocal,
		Local:  &v,
	}
}

// NewPrivateIEIDGlobal creates a PrivateIEID with the global alternative.
func BridgeNewPrivateIEIDGlobalLegacy(v runtime.ObjectIdentifier) s23.PrivateIEID {
	return s23.PrivateIEID{
		Choice: s00.PrivateIEIDChoiceGlobal,
		Global: &v,
	}
}

// NewPrivateIEIDLocal constructs a checked complete value.
func NewPrivateIEIDLocal(v int64, options ...aper.BuildOption) (s23.PrivateIEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s23.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDLocal")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s23.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDLocal")
	}
	value := BridgeNewPrivateIEIDLocalLegacy(v)
	if _, err := s23.BridgePrivateIEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s23.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDLocal")
	}
	return value, aper.OperationError(nil, "PrivateIEIDLocal")
}

// NewPrivateIEIDGlobal constructs a checked complete value.
func NewPrivateIEIDGlobal(v runtime.ObjectIdentifier, options ...aper.BuildOption) (s23.PrivateIEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s23.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDGlobal")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s23.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDGlobal")
	}
	value := BridgeNewPrivateIEIDGlobalLegacy(v)
	if _, err := s23.BridgePrivateIEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s23.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDGlobal")
	}
	return value, aper.OperationError(nil, "PrivateIEIDGlobal")
}

// NewCauseRadioNetwork creates a Cause with the radioNetwork alternative.
func BridgeNewCauseRadioNetworkLegacy(v s00.CauseRadioNetwork) s17.Cause {
	return s17.Cause{
		Choice:       s00.CauseChoiceRadioNetwork,
		RadioNetwork: &v,
	}
}

// NewCauseTransport creates a Cause with the transport alternative.
func BridgeNewCauseTransportLegacy(v s00.CauseTransport) s17.Cause {
	return s17.Cause{
		Choice:    s00.CauseChoiceTransport,
		Transport: &v,
	}
}

// NewCauseNas creates a Cause with the nas alternative.
func BridgeNewCauseNasLegacy(v s00.CauseNas) s17.Cause {
	return s17.Cause{
		Choice: s00.CauseChoiceNas,
		Nas:    &v,
	}
}

// NewCauseProtocol creates a Cause with the protocol alternative.
func BridgeNewCauseProtocolLegacy(v s00.CauseProtocol) s17.Cause {
	return s17.Cause{
		Choice:   s00.CauseChoiceProtocol,
		Protocol: &v,
	}
}

// NewCauseMisc creates a Cause with the misc alternative.
func BridgeNewCauseMiscLegacy(v s00.CauseMisc) s17.Cause {
	return s17.Cause{
		Choice: s00.CauseChoiceMisc,
		Misc:   &v,
	}
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12 creates a DLCOUNTPDCPSNlength with the dLCOUNTValuePDCP-SNlength12 alternative.
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12Legacy(v s16.COUNTvalue) s17.DLCOUNTPDCPSNlength {
	return s17.DLCOUNTPDCPSNlength{
		Choice:                     s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12,
		DLCOUNTValuePDCPSNlength12: &v,
	}
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15 creates a DLCOUNTPDCPSNlength with the dLCOUNTValuePDCP-SNlength15 alternative.
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15Legacy(v s16.COUNTValueExtended) s17.DLCOUNTPDCPSNlength {
	return s17.DLCOUNTPDCPSNlength{
		Choice:                     s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15,
		DLCOUNTValuePDCPSNlength15: &v,
	}
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18 creates a DLCOUNTPDCPSNlength with the dLCOUNTValuePDCP-SNlength18 alternative.
func BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18Legacy(v s16.COUNTvaluePDCPSNlength18) s17.DLCOUNTPDCPSNlength {
	return s17.DLCOUNTPDCPSNlength{
		Choice:                     s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18,
		DLCOUNTValuePDCPSNlength18: &v,
	}
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12 creates a DLDiscarding with the discardDLCOUNTValuePDCP-SNlength12 alternative.
func BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12Legacy(v s16.COUNTvalue) s17.DLDiscarding {
	return s17.DLDiscarding{
		Choice:                            s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength12,
		DiscardDLCOUNTValuePDCPSNlength12: &v,
	}
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15 creates a DLDiscarding with the discardDLCOUNTValuePDCP-SNlength15 alternative.
func BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15Legacy(v s16.COUNTValueExtended) s17.DLDiscarding {
	return s17.DLDiscarding{
		Choice:                            s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15,
		DiscardDLCOUNTValuePDCPSNlength15: &v,
	}
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18 creates a DLDiscarding with the discardDLCOUNTValuePDCP-SNlength18 alternative.
func BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18Legacy(v s16.COUNTvaluePDCPSNlength18) s17.DLDiscarding {
	return s17.DLDiscarding{
		Choice:                            s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18,
		DiscardDLCOUNTValuePDCPSNlength18: &v,
	}
}

// NewENBIDMacroENBID creates a ENBID with the macroENB-ID alternative.
func BridgeNewENBIDMacroENBIDLegacy(v runtime.BitString) s18.ENBID {
	return s18.ENBID{
		Choice:     s00.ENBIDChoiceMacroENBID,
		MacroENBID: &v,
	}
}

// NewENBIDHomeENBID creates a ENBID with the homeENB-ID alternative.
func BridgeNewENBIDHomeENBIDLegacy(v runtime.BitString) s18.ENBID {
	return s18.ENBID{
		Choice:    s00.ENBIDChoiceHomeENBID,
		HomeENBID: &v,
	}
}

// NewENBIDShortMacroENBID creates a ENBID with the short-macroENB-ID alternative.
func BridgeNewENBIDShortMacroENBIDLegacy(v runtime.BitString) s18.ENBID {
	return s18.ENBID{
		Choice:          s00.ENBIDChoiceShortMacroENBID,
		ShortMacroENBID: &v,
	}
}

// NewENBIDLongMacroENBID creates a ENBID with the long-macroENB-ID alternative.
func BridgeNewENBIDLongMacroENBIDLegacy(v runtime.BitString) s18.ENBID {
	return s18.ENBID{
		Choice:         s00.ENBIDChoiceLongMacroENBID,
		LongMacroENBID: &v,
	}
}

// NewEventTriggerOutOfCoverage creates a EventTrigger with the outOfCoverage alternative.
func BridgeNewEventTriggerOutOfCoverageLegacy(v int64) s22.EventTrigger {
	return s22.EventTrigger{
		Choice:        s00.EventTriggerChoiceOutOfCoverage,
		OutOfCoverage: &v,
	}
}

// NewEventTriggerEventL1LoggedMDTConfig creates a EventTrigger with the eventL1LoggedMDTConfig alternative.
func BridgeNewEventTriggerEventL1LoggedMDTConfigLegacy(v s22.EventL1LoggedMDTConfig) s22.EventTrigger {
	return s22.EventTrigger{
		Choice:                 s00.EventTriggerChoiceEventL1LoggedMDTConfig,
		EventL1LoggedMDTConfig: &v,
	}
}

// NewEventTriggerChoiceExtensions creates a EventTrigger with the choice-Extensions alternative.
func BridgeNewEventTriggerChoiceExtensionsLegacy(v s10.EventTriggerExtIEValueProtocolIESingleContainer) s22.EventTrigger {
	return s22.EventTrigger{
		Choice:           s00.EventTriggerChoiceChoiceExtensions,
		ChoiceExtensions: &v,
	}
}

// NewLastVisitedGERANCellInformationUndefined creates a LastVisitedGERANCellInformation with the undefined alternative.
func BridgeNewLastVisitedGERANCellInformationUndefinedLegacy(v struct{}) s22.LastVisitedGERANCellInformation {
	return s22.LastVisitedGERANCellInformation{
		Choice:    s00.LastVisitedGERANCellInformationChoiceUndefined,
		Undefined: &v,
	}
}

// NewLoggedMDTTriggerPeriodical creates a LoggedMDTTrigger with the periodical alternative.
func BridgeNewLoggedMDTTriggerPeriodicalLegacy(v struct{}) s22.LoggedMDTTrigger {
	return s22.LoggedMDTTrigger{
		Choice:     s00.LoggedMDTTriggerChoicePeriodical,
		Periodical: &v,
	}
}

// NewLoggedMDTTriggerEventTrigger creates a LoggedMDTTrigger with the eventTrigger alternative.
func BridgeNewLoggedMDTTriggerEventTriggerLegacy(v s22.EventTrigger) s22.LoggedMDTTrigger {
	return s22.LoggedMDTTrigger{
		Choice:       s00.LoggedMDTTriggerChoiceEventTrigger,
		EventTrigger: &v,
	}
}

// NewMeasurementThresholdA2ThresholdRSRP creates a MeasurementThresholdA2 with the threshold-RSRP alternative.
func BridgeNewMeasurementThresholdA2ThresholdRSRPLegacy(v s00.ThresholdRSRP) s22.MeasurementThresholdA2 {
	return s22.MeasurementThresholdA2{
		Choice:        s00.MeasurementThresholdA2ChoiceThresholdRSRP,
		ThresholdRSRP: &v,
	}
}

// NewMeasurementThresholdA2ThresholdRSRQ creates a MeasurementThresholdA2 with the threshold-RSRQ alternative.
func BridgeNewMeasurementThresholdA2ThresholdRSRQLegacy(v s00.ThresholdRSRQ) s22.MeasurementThresholdA2 {
	return s22.MeasurementThresholdA2{
		Choice:        s00.MeasurementThresholdA2ChoiceThresholdRSRQ,
		ThresholdRSRQ: &v,
	}
}

// NewMeasurementThresholdL1LoggedMDTThresholdRSRP creates a MeasurementThresholdL1LoggedMDT with the threshold-RSRP alternative.
func BridgeNewMeasurementThresholdL1LoggedMDTThresholdRSRPLegacy(v s00.ThresholdRSRP) s22.MeasurementThresholdL1LoggedMDT {
	return s22.MeasurementThresholdL1LoggedMDT{
		Choice:        s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRP,
		ThresholdRSRP: &v,
	}
}

// NewMeasurementThresholdL1LoggedMDTThresholdRSRQ creates a MeasurementThresholdL1LoggedMDT with the threshold-RSRQ alternative.
func BridgeNewMeasurementThresholdL1LoggedMDTThresholdRSRQLegacy(v s00.ThresholdRSRQ) s22.MeasurementThresholdL1LoggedMDT {
	return s22.MeasurementThresholdL1LoggedMDT{
		Choice:        s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ,
		ThresholdRSRQ: &v,
	}
}

// NewMeasurementThresholdL1LoggedMDTChoiceExtensions creates a MeasurementThresholdL1LoggedMDT with the choice-Extensions alternative.
func BridgeNewMeasurementThresholdL1LoggedMDTChoiceExtensionsLegacy(v s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer) s22.MeasurementThresholdL1LoggedMDT {
	return s22.MeasurementThresholdL1LoggedMDT{
		Choice:           s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions,
		ChoiceExtensions: &v,
	}
}

// NewOverloadResponseOverloadAction creates a OverloadResponse with the overloadAction alternative.
func BridgeNewOverloadResponseOverloadActionLegacy(v s00.OverloadAction) s23.OverloadResponse {
	return s23.OverloadResponse{
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
	IEExtensions             s12.RecommendedCellsForPagingExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	EUTRANCGI         s20.EUTRANCGI                                       `asn1:"tag:0,context,implicit"`
	TimeStayedInCell  *int64                                              `asn1:"tag:1,context,implicit,optional" json:"TimeStayedInCell,omitempty"`
	IEExtensions      s12.RecommendedCellsForPagingItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                `asn1:"-" json:"-"`
	extCount          int64                                               `asn1:"-" json:"-"`
	extPresent        []bool                                              `asn1:"-" json:"-"`
	extData           [][]byte                                            `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                   `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                              `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// NewSONInformationReportRLFReportInformation creates a SONInformationReport with the rLFReportInformation alternative.
func BridgeNewSONInformationReportRLFReportInformationLegacy(v s23.RLFReportInformation) s24.SONInformationReport {
	return s24.SONInformationReport{
		Choice:               s00.SONInformationReportChoiceRLFReportInformation,
		RLFReportInformation: &v,
	}
}

// NewGlobalRANNODEIDGNB creates a GlobalRANNODEID with the gNB alternative.
func BridgeNewGlobalRANNODEIDGNBLegacy(v s21.GNB) s23.GlobalRANNODEID {
	return s23.GlobalRANNODEID{
		Choice: s00.GlobalRANNODEIDChoiceGNB,
		GNB:    &v,
	}
}

// NewGlobalRANNODEIDNgENB creates a GlobalRANNODEID with the ng-eNB alternative.
func BridgeNewGlobalRANNODEIDNgENBLegacy(v s23.NGENB) s23.GlobalRANNODEID {
	return s23.GlobalRANNODEID{
		Choice: s00.GlobalRANNODEIDChoiceNgENB,
		NgENB:  &v,
	}
}

// NewGNBIdentityGNBID creates a GNBIdentity with the gNB-ID alternative.
func BridgeNewGNBIdentityGNBIDLegacy(v s00.GNBID) s21.GNBIdentity {
	return s21.GNBIdentity{
		Choice: s00.GNBIdentityChoiceGNBID,
		GNBID:  &v,
	}
}

// MarshalAPERBearersSubjectToStatusTransferListTo appends a BearersSubjectToStatusTransferList list to bb.
func BridgeMarshalAPERBearersSubjectToStatusTransferListTo(list s25.BearersSubjectToStatusTransferList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERBearersSubjectToStatusTransferListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s25.BridgeBearersSubjectToStatusTransferItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERBearersSubjectToEarlyStatusTransferListTo(list s17.BearersSubjectToEarlyStatusTransferList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERBearersSubjectToEarlyStatusTransferListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERBearersSubjectToDLDiscardingListTo(list s17.BearersSubjectToDLDiscardingList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCancelledCellinEAITo(list s20.CancelledCellinEAI, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCancelledCellinEAIListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeCancelledCellinEAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCancelledCellinTAITo(list s20.CancelledCellinTAI, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCancelledCellinTAIListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeCancelledCellinTAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCellIDBroadcastTo(list s20.CellIDBroadcast, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCellIDBroadcastListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeCellIDBroadcastItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCellIDCancelledTo(list s20.CellIDCancelled, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCellIDCancelledListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeCellIDCancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCellIdListforMDTTo(list s20.CellIdListforMDT, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCellIdListforMDTListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCellIdListforQMCTo(list s20.CellIdListforQMC, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCellIdListforQMCListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCNTypeRestrictionsTo(list s16.CNTypeRestrictions, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCNTypeRestrictionsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeCNTypeRestrictionsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCSGIdListTo(list s17.CSGIdList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCSGIdListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCSGIdListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCriticalityDiagnosticsIEListTo(list s17.CriticalityDiagnosticsIEList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERDAPSResponseInfoListTo(list s17.DAPSResponseInfoList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERDAPSResponseInfoListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERECGIListTo(list s20.ECGIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERECGIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERPWSfailedECGIListTo(list s23.PWSfailedECGIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERPWSfailedECGIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPEREmergencyAreaIDBroadcastTo(list s26.EmergencyAreaIDBroadcast, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s26.BridgeAsn1cAPEREmergencyAreaIDBroadcastListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s26.BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPEREmergencyAreaIDCancelledTo(list s25.EmergencyAreaIDCancelled, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPEREmergencyAreaIDCancelledListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s25.BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCompletedCellinEAITo(list s20.CompletedCellinEAI, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCompletedCellinEAIListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeCompletedCellinEAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERIEsECGIListTo(list s21.IEsECGIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERIEsECGIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERGUMMEIListTo(list s21.GUMMEIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERGUMMEIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s21.BridgeGUMMEIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABListTo(list s19.ERABList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeERABItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABUsageReportListTo(list s20.ERABUsageReportList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABUsageReportListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeERABUsageReportItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERForbiddenTAsTo(list s21.ForbiddenTAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERForbiddenTAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s21.BridgeForbiddenTAsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERForbiddenLAsTo(list s21.ForbiddenLAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERForbiddenLAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s21.BridgeForbiddenLAsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERInterSystemMeasurementListTo(list s21.InterSystemMeasurementList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERInterSystemMeasurementListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s21.BridgeInterSystemMeasurementItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERLastVisitedPSCellListTo(list s23.LastVisitedPSCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERLastVisitedPSCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s23.BridgeLastVisitedPSCellInformationMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERMBSFNResultToLogTo(list s22.MBSFNResultToLog, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERMBSFNResultToLogListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s22.BridgeMBSFNResultToLogInfoMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERPC5QoSFlowListTo(list s23.PC5QoSFlowList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERPC5QoSFlowListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s23.BridgePC5QoSFlowItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s12.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RecommendedCellsForPaging from APER format.
func (v *RecommendedCellsForPaging) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *RecommendedCellsForPaging) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellsForPaging{}
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
	toleranceMark_recommendedcelllist := bb.EnterComponent("RecommendedCellList")
	v.RecommendedCellList = make(RecommendedCellList, 0)
	_, errCollection_recommendedcelllist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_recommendedcelllist, fragmentLength_recommendedcelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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
		tmp_ieextensions := make(s12.RecommendedCellsForPagingExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.RecommendedCellsForPagingExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeRecommendedCellsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := aper.EncodeBoolean(bb, v.TimeStayedInCell != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&v.EUTRANCGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eUTRAN-CGI: %w", err)
	}
	if v.TimeStayedInCell != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.TimeStayedInCell), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4095), false); err != nil {
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
				if err := s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RecommendedCellItem from APER format.
func (v *RecommendedCellItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *RecommendedCellItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellItem{}
	var extAdditions aper.ExtensionAdditions
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
	if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&v.EUTRANCGI, bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANCGI")
	}
	bb.LeaveComponent(toleranceMark_eutrancgi)
	if opt_timestayedincell {
		val_timestayedincell, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4095), false)
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
		tmp_ieextensions := make(s12.RecommendedCellsForPagingItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.RecommendedCellsForPagingItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERRATRestrictionsTo appends a RATRestrictions list to bb.
func BridgeMarshalAPERRATRestrictionsTo(list s23.RATRestrictions, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERRATRestrictionsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s23.BridgeRATRestrictionsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERECGIListForRestartTo(list s20.ECGIListForRestart, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERECGIListForRestartListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCompletedCellinTAITo(list s20.CompletedCellinTAI, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCompletedCellinTAIListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeCompletedCellinTAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERENBX2ExtTLAsTo(list s18.ENBX2ExtTLAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERENBX2ExtTLAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeENBX2ExtTLAMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func (v *RecommendedCellItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "RecommendedCellItem", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "RecommendedCellsForPaging", v.receivedLocation, v.perPadding)
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

// NewCauseRadioNetwork constructs a checked complete value.
func NewCauseRadioNetwork(v s00.CauseRadioNetwork, options ...aper.BuildOption) (s17.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseRadioNetwork")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseRadioNetwork")
	}
	value := BridgeNewCauseRadioNetworkLegacy(v)
	if _, err := s17.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseRadioNetwork")
	}
	return value, aper.OperationError(nil, "CauseRadioNetwork")
}

// NewCauseTransport constructs a checked complete value.
func NewCauseTransport(v s00.CauseTransport, options ...aper.BuildOption) (s17.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseTransport")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseTransport")
	}
	value := BridgeNewCauseTransportLegacy(v)
	if _, err := s17.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseTransport")
	}
	return value, aper.OperationError(nil, "CauseTransport")
}

// NewCauseNas constructs a checked complete value.
func NewCauseNas(v s00.CauseNas, options ...aper.BuildOption) (s17.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseNas")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseNas")
	}
	value := BridgeNewCauseNasLegacy(v)
	if _, err := s17.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseNas")
	}
	return value, aper.OperationError(nil, "CauseNas")
}

// NewCauseProtocol constructs a checked complete value.
func NewCauseProtocol(v s00.CauseProtocol, options ...aper.BuildOption) (s17.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseProtocol")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseProtocol")
	}
	value := BridgeNewCauseProtocolLegacy(v)
	if _, err := s17.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseProtocol")
	}
	return value, aper.OperationError(nil, "CauseProtocol")
}

// NewCauseMisc constructs a checked complete value.
func NewCauseMisc(v s00.CauseMisc, options ...aper.BuildOption) (s17.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseMisc")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseMisc")
	}
	value := BridgeNewCauseMiscLegacy(v)
	if _, err := s17.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.Cause{}, aper.OperationError(err, "CauseMisc")
	}
	return value, aper.OperationError(nil, "CauseMisc")
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12 constructs a checked complete value.
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12(v s16.COUNTvalue, options ...aper.BuildOption) (s17.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12Legacy(v)
	if _, err := s17.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12")
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15 constructs a checked complete value.
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15(v s16.COUNTValueExtended, options ...aper.BuildOption) (s17.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15Legacy(v)
	if _, err := s17.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength15")
}

// NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18 constructs a checked complete value.
func NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18(v s16.COUNTvaluePDCPSNlength18, options ...aper.BuildOption) (s17.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
	}
	value := BridgeNewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18Legacy(v)
	if _, err := s17.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength18")
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12 constructs a checked complete value.
func NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12(v s16.COUNTvalue, options ...aper.BuildOption) (s17.DLDiscarding, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength12")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength12")
	}
	value := BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength12Legacy(v)
	if _, err := s17.BridgeDLDiscardingMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength12")
	}
	return value, aper.OperationError(nil, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength12")
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15 constructs a checked complete value.
func NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15(v s16.COUNTValueExtended, options ...aper.BuildOption) (s17.DLDiscarding, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength15")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength15")
	}
	value := BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength15Legacy(v)
	if _, err := s17.BridgeDLDiscardingMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength15")
	}
	return value, aper.OperationError(nil, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength15")
}

// NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18 constructs a checked complete value.
func NewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18(v s16.COUNTvaluePDCPSNlength18, options ...aper.BuildOption) (s17.DLDiscarding, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength18")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength18")
	}
	value := BridgeNewDLDiscardingDiscardDLCOUNTValuePDCPSNlength18Legacy(v)
	if _, err := s17.BridgeDLDiscardingMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s17.DLDiscarding{}, aper.OperationError(err, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength18")
	}
	return value, aper.OperationError(nil, "DLDiscardingDiscardDLCOUNTValuePDCPSNlength18")
}

// NewENBIDMacroENBID constructs a checked complete value.
func NewENBIDMacroENBID(v runtime.BitString, options ...aper.BuildOption) (s18.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDMacroENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDMacroENBID")
	}
	value := BridgeNewENBIDMacroENBIDLegacy(v)
	if _, err := s18.BridgeENBIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDMacroENBID")
	}
	return value, aper.OperationError(nil, "ENBIDMacroENBID")
}

// NewENBIDHomeENBID constructs a checked complete value.
func NewENBIDHomeENBID(v runtime.BitString, options ...aper.BuildOption) (s18.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDHomeENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDHomeENBID")
	}
	value := BridgeNewENBIDHomeENBIDLegacy(v)
	if _, err := s18.BridgeENBIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDHomeENBID")
	}
	return value, aper.OperationError(nil, "ENBIDHomeENBID")
}

// NewENBIDShortMacroENBID constructs a checked complete value.
func NewENBIDShortMacroENBID(v runtime.BitString, options ...aper.BuildOption) (s18.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDShortMacroENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDShortMacroENBID")
	}
	value := BridgeNewENBIDShortMacroENBIDLegacy(v)
	if _, err := s18.BridgeENBIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDShortMacroENBID")
	}
	return value, aper.OperationError(nil, "ENBIDShortMacroENBID")
}

// NewENBIDLongMacroENBID constructs a checked complete value.
func NewENBIDLongMacroENBID(v runtime.BitString, options ...aper.BuildOption) (s18.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDLongMacroENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDLongMacroENBID")
	}
	value := BridgeNewENBIDLongMacroENBIDLegacy(v)
	if _, err := s18.BridgeENBIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s18.ENBID{}, aper.OperationError(err, "ENBIDLongMacroENBID")
	}
	return value, aper.OperationError(nil, "ENBIDLongMacroENBID")
}

// NewEventTriggerOutOfCoverage constructs a checked complete value.
func NewEventTriggerOutOfCoverage(v int64, options ...aper.BuildOption) (s22.EventTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerOutOfCoverage")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerOutOfCoverage")
	}
	value := BridgeNewEventTriggerOutOfCoverageLegacy(v)
	if _, err := s22.BridgeEventTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerOutOfCoverage")
	}
	return value, aper.OperationError(nil, "EventTriggerOutOfCoverage")
}

// NewEventTriggerEventL1LoggedMDTConfig constructs a checked complete value.
func NewEventTriggerEventL1LoggedMDTConfig(v s22.EventL1LoggedMDTConfig, options ...aper.BuildOption) (s22.EventTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerEventL1LoggedMDTConfig")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerEventL1LoggedMDTConfig")
	}
	value := BridgeNewEventTriggerEventL1LoggedMDTConfigLegacy(v)
	if _, err := s22.BridgeEventTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerEventL1LoggedMDTConfig")
	}
	return value, aper.OperationError(nil, "EventTriggerEventL1LoggedMDTConfig")
}

// NewEventTriggerChoiceExtensions constructs a checked complete value.
func NewEventTriggerChoiceExtensions(v s10.EventTriggerExtIEValueProtocolIESingleContainer, options ...aper.BuildOption) (s22.EventTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerChoiceExtensions")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerChoiceExtensions")
	}
	value := BridgeNewEventTriggerChoiceExtensionsLegacy(v)
	if _, err := s22.BridgeEventTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.EventTrigger{}, aper.OperationError(err, "EventTriggerChoiceExtensions")
	}
	return value, aper.OperationError(nil, "EventTriggerChoiceExtensions")
}

// NewLastVisitedGERANCellInformationUndefined constructs a checked complete value.
func NewLastVisitedGERANCellInformationUndefined(v struct{}, options ...aper.BuildOption) (s22.LastVisitedGERANCellInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUndefined")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUndefined")
	}
	value := BridgeNewLastVisitedGERANCellInformationUndefinedLegacy(v)
	if _, err := s22.BridgeLastVisitedGERANCellInformationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUndefined")
	}
	return value, aper.OperationError(nil, "LastVisitedGERANCellInformationUndefined")
}

// NewLoggedMDTTriggerPeriodical constructs a checked complete value.
func NewLoggedMDTTriggerPeriodical(v struct{}, options ...aper.BuildOption) (s22.LoggedMDTTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerPeriodical")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerPeriodical")
	}
	value := BridgeNewLoggedMDTTriggerPeriodicalLegacy(v)
	if _, err := s22.BridgeLoggedMDTTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerPeriodical")
	}
	return value, aper.OperationError(nil, "LoggedMDTTriggerPeriodical")
}

// NewLoggedMDTTriggerEventTrigger constructs a checked complete value.
func NewLoggedMDTTriggerEventTrigger(v s22.EventTrigger, options ...aper.BuildOption) (s22.LoggedMDTTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerEventTrigger")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerEventTrigger")
	}
	value := BridgeNewLoggedMDTTriggerEventTriggerLegacy(v)
	if _, err := s22.BridgeLoggedMDTTriggerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerEventTrigger")
	}
	return value, aper.OperationError(nil, "LoggedMDTTriggerEventTrigger")
}

// NewMeasurementThresholdA2ThresholdRSRP constructs a checked complete value.
func NewMeasurementThresholdA2ThresholdRSRP(v s00.ThresholdRSRP, options ...aper.BuildOption) (s22.MeasurementThresholdA2, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRP")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRP")
	}
	value := BridgeNewMeasurementThresholdA2ThresholdRSRPLegacy(v)
	if _, err := s22.BridgeMeasurementThresholdA2MethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRP")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdA2ThresholdRSRP")
}

// NewMeasurementThresholdA2ThresholdRSRQ constructs a checked complete value.
func NewMeasurementThresholdA2ThresholdRSRQ(v s00.ThresholdRSRQ, options ...aper.BuildOption) (s22.MeasurementThresholdA2, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRQ")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRQ")
	}
	value := BridgeNewMeasurementThresholdA2ThresholdRSRQLegacy(v)
	if _, err := s22.BridgeMeasurementThresholdA2MethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2ThresholdRSRQ")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdA2ThresholdRSRQ")
}

// NewMeasurementThresholdL1LoggedMDTThresholdRSRP constructs a checked complete value.
func NewMeasurementThresholdL1LoggedMDTThresholdRSRP(v s00.ThresholdRSRP, options ...aper.BuildOption) (s22.MeasurementThresholdL1LoggedMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRP")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRP")
	}
	value := BridgeNewMeasurementThresholdL1LoggedMDTThresholdRSRPLegacy(v)
	if _, err := s22.BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRP")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdL1LoggedMDTThresholdRSRP")
}

// NewMeasurementThresholdL1LoggedMDTThresholdRSRQ constructs a checked complete value.
func NewMeasurementThresholdL1LoggedMDTThresholdRSRQ(v s00.ThresholdRSRQ, options ...aper.BuildOption) (s22.MeasurementThresholdL1LoggedMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRQ")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRQ")
	}
	value := BridgeNewMeasurementThresholdL1LoggedMDTThresholdRSRQLegacy(v)
	if _, err := s22.BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTThresholdRSRQ")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdL1LoggedMDTThresholdRSRQ")
}

// NewMeasurementThresholdL1LoggedMDTChoiceExtensions constructs a checked complete value.
func NewMeasurementThresholdL1LoggedMDTChoiceExtensions(v s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer, options ...aper.BuildOption) (s22.MeasurementThresholdL1LoggedMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTChoiceExtensions")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTChoiceExtensions")
	}
	value := BridgeNewMeasurementThresholdL1LoggedMDTChoiceExtensionsLegacy(v)
	if _, err := s22.BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MeasurementThresholdL1LoggedMDT{}, aper.OperationError(err, "MeasurementThresholdL1LoggedMDTChoiceExtensions")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdL1LoggedMDTChoiceExtensions")
}

// NewOverloadResponseOverloadAction constructs a checked complete value.
func NewOverloadResponseOverloadAction(v s00.OverloadAction, options ...aper.BuildOption) (s23.OverloadResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s23.OverloadResponse{}, aper.OperationError(err, "OverloadResponseOverloadAction")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s23.OverloadResponse{}, aper.OperationError(err, "OverloadResponseOverloadAction")
	}
	value := BridgeNewOverloadResponseOverloadActionLegacy(v)
	if _, err := s23.BridgeOverloadResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s23.OverloadResponse{}, aper.OperationError(err, "OverloadResponseOverloadAction")
	}
	return value, aper.OperationError(nil, "OverloadResponseOverloadAction")
}

// NewSONInformationReportRLFReportInformation constructs a checked complete value.
func NewSONInformationReportRLFReportInformation(v s23.RLFReportInformation, options ...aper.BuildOption) (s24.SONInformationReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONInformationReport{}, aper.OperationError(err, "SONInformationReportRLFReportInformation")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONInformationReport{}, aper.OperationError(err, "SONInformationReportRLFReportInformation")
	}
	value := BridgeNewSONInformationReportRLFReportInformationLegacy(v)
	if _, err := s24.BridgeSONInformationReportMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONInformationReport{}, aper.OperationError(err, "SONInformationReportRLFReportInformation")
	}
	return value, aper.OperationError(nil, "SONInformationReportRLFReportInformation")
}

// NewGlobalRANNODEIDGNB constructs a checked complete value.
func NewGlobalRANNODEIDGNB(v s21.GNB, options ...aper.BuildOption) (s23.GlobalRANNODEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s23.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDGNB")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s23.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDGNB")
	}
	value := BridgeNewGlobalRANNODEIDGNBLegacy(v)
	if _, err := s23.BridgeGlobalRANNODEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s23.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDGNB")
	}
	return value, aper.OperationError(nil, "GlobalRANNODEIDGNB")
}

// NewGlobalRANNODEIDNgENB constructs a checked complete value.
func NewGlobalRANNODEIDNgENB(v s23.NGENB, options ...aper.BuildOption) (s23.GlobalRANNODEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s23.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDNgENB")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s23.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDNgENB")
	}
	value := BridgeNewGlobalRANNODEIDNgENBLegacy(v)
	if _, err := s23.BridgeGlobalRANNODEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s23.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDNgENB")
	}
	return value, aper.OperationError(nil, "GlobalRANNODEIDNgENB")
}

// NewGNBIdentityGNBID constructs a checked complete value.
func NewGNBIdentityGNBID(v s00.GNBID, options ...aper.BuildOption) (s21.GNBIdentity, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.GNBIdentity{}, aper.OperationError(err, "GNBIdentityGNBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.GNBIdentity{}, aper.OperationError(err, "GNBIdentityGNBID")
	}
	value := BridgeNewGNBIdentityGNBIDLegacy(v)
	if _, err := s21.BridgeGNBIdentityMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.GNBIdentity{}, aper.OperationError(err, "GNBIdentityGNBID")
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
	ProtocolIEs      s27.PathSwitchRequestFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
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
	ProtocolIEs      s26.InitialContextSetupFailureIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s22.NASNonDeliveryIndicationIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s26.MMEConfigurationUpdateAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s27.MMEConfigurationUpdateFailureIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s25.MMEStatusTransferIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s22.LocationReportingFailureIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
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
	PrivateIEs       s29.PrivateMessageIEsValuePrivateIEContainer `asn1:"tag:0,context,implicit"`
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
func BridgeMarshalAPERERABSubjecttoDataForwardingListTo(list s20.ERABSubjecttoDataForwardingList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABSubjecttoDataForwardingListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeERABDataForwardingItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABAdmittedListTo(list s18.ERABAdmittedList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABAdmittedListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeERABAdmittedItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABFailedtoSetupListHOReqAckTo(list s19.ERABFailedtoSetupListHOReqAck, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABFailedtoSetupListHOReqAckListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABToBeSwitchedULListTo(list s20.ERABToBeSwitchedULList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABToBeSwitchedULListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeERABToBeSwitchedULItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
			if err := s27.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PathSwitchRequestFailure from APER format.
func (v *PathSwitchRequestFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *PathSwitchRequestFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s27.PathSwitchRequestFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s27.PathSwitchRequestFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s27.BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABSetupListBearerSUResTo appends a ERABSetupListBearerSURes list to bb.
func BridgeMarshalAPERERABSetupListBearerSUResTo(list s20.ERABSetupListBearerSURes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABSetupListBearerSUResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeERABSetupItemBearerSUResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABToBeModifiedListBearerModReqTo(list s29.ERABToBeModifiedListBearerModReq, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s29.BridgeAsn1cAPERERABToBeModifiedListBearerModReqListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s29.BridgeERABToBeModifiedItemBearerModReqIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABModifyListBearerModResTo(list s19.ERABModifyListBearerModRes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABModifyListBearerModResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeERABModifyItemBearerModResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABReleaseListBearerRelCompTo(list s19.ERABReleaseListBearerRelComp, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABReleaseListBearerRelCompListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeERABReleaseItemBearerRelCompIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABSetupListCtxtSUResTo(list s20.ERABSetupListCtxtSURes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABSetupListCtxtSUResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
			if err := s26.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes InitialContextSetupFailure from APER format.
func (v *InitialContextSetupFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *InitialContextSetupFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitialContextSetupFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s26.InitialContextSetupFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s26.InitialContextSetupFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s26.BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NASNonDeliveryIndication from APER format.
func (v *NASNonDeliveryIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *NASNonDeliveryIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NASNonDeliveryIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s22.NASNonDeliveryIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.NASNonDeliveryIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMEConfigurationUpdateAcknowledge from APER format.
func (v *MMEConfigurationUpdateAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *MMEConfigurationUpdateAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdateAcknowledge{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s26.MMEConfigurationUpdateAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s26.MMEConfigurationUpdateAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s26.BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMEConfigurationUpdateFailure from APER format.
func (v *MMEConfigurationUpdateFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *MMEConfigurationUpdateFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdateFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s27.MMEConfigurationUpdateFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s26.MMEConfigurationUpdateFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s26.BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s25.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMEStatusTransfer from APER format.
func (v *MMEStatusTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *MMEStatusTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEStatusTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s25.MMEStatusTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s25.MMEStatusTransferIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s25.BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LocationReportingFailureIndication from APER format.
func (v *LocationReportingFailureIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *LocationReportingFailureIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LocationReportingFailureIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s22.LocationReportingFailureIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s22.LocationReportingFailureIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := aper.EncodeCollection(bb, int64(len(v.PrivateIEs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_privateies < 0 || fragmentOffset_privateies > int64(len(v.PrivateIEs)) || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(len(v.PrivateIEs[fragmentOffset_privateies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PrivateIEs[fragmentOffset_privateies : fragmentOffset_privateies+fragmentLength_privateies] {
			if err := s29.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PrivateMessage from APER format.
func (v *PrivateMessage) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *PrivateMessage) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateMessage{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_privateies := bb.EnterComponent("PrivateIEs")
	v.PrivateIEs = make(s29.PrivateMessageIEsValuePrivateIEContainer, 0)
	_, errCollection_privateies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_privateies < 0 || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(^uint(0)>>1) || fragmentOffset_privateies > int64(^uint(0)>>1)-fragmentLength_privateies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_privateies; i++ {
			var elem s29.PrivateMessageIEsValuePrivateIEField
			elementMark := bb.EnterIndex(fragmentOffset_privateies + i)
			if err := s29.BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERERABToBeModifiedListBearerModIndTo appends a ERABToBeModifiedListBearerModInd list to bb.
func BridgeMarshalAPERERABToBeModifiedListBearerModIndTo(list s20.ERABToBeModifiedListBearerModInd, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABToBeModifiedListBearerModIndListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s20.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABNotToBeModifiedListBearerModIndTo(list s19.ERABNotToBeModifiedListBearerModInd, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABNotToBeModifiedListBearerModIndListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABModifyListBearerModConfTo(list s19.ERABModifyListBearerModConf, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABModifyListBearerModConfListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeERABModifyItemBearerModConfIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABFailedToResumeListResumeReqTo(list s18.ERABFailedToResumeListResumeReq, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABFailedToResumeListResumeReqListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERERABFailedToResumeListResumeResTo(list s18.ERABFailedToResumeListResumeRes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERERABFailedToResumeListResumeResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func (v *InitialContextSetupFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "InitialContextSetupFailure", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "LocationReportingFailureIndication", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEConfigurationUpdateAcknowledge", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEConfigurationUpdateFailure", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEStatusTransfer", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "NASNonDeliveryIndication", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "PathSwitchRequestFailure", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "PrivateMessage", v.receivedLocation, v.perPadding)
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
func BridgeNewSONtransferRequestContainerCellLoadReportingLegacy(v struct{}) s28.SONtransferRequestContainer {
	return s28.SONtransferRequestContainer{
		Choice:            s00.SONtransferRequestContainerChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerMultiCellLoadReporting creates a SONtransferRequestContainer with the multiCellLoadReporting alternative.
func BridgeNewSONtransferRequestContainerMultiCellLoadReportingLegacy(v s28.MultiCellLoadReportingRequest) s28.SONtransferRequestContainer {
	return s28.SONtransferRequestContainer{
		Choice:                 s00.SONtransferRequestContainerChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerEventTriggeredCellLoadReporting creates a SONtransferRequestContainer with the eventTriggeredCellLoadReporting alternative.
func BridgeNewSONtransferRequestContainerEventTriggeredCellLoadReportingLegacy(v s21.EventTriggeredCellLoadReportingRequest) s28.SONtransferRequestContainer {
	return s28.SONtransferRequestContainer{
		Choice:                          s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerHOReporting creates a SONtransferRequestContainer with the hOReporting alternative.
func BridgeNewSONtransferRequestContainerHOReportingLegacy(v s25.HOReport) s28.SONtransferRequestContainer {
	return s28.SONtransferRequestContainer{
		Choice:      s00.SONtransferRequestContainerChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferRequestContainerEutranCellActivation creates a SONtransferRequestContainer with the eutranCellActivation alternative.
func BridgeNewSONtransferRequestContainerEutranCellActivationLegacy(v s26.CellActivationRequest) s28.SONtransferRequestContainer {
	return s28.SONtransferRequestContainer{
		Choice:               s00.SONtransferRequestContainerChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferRequestContainerEnergySavingsIndication creates a SONtransferRequestContainer with the energySavingsIndication alternative.
func BridgeNewSONtransferRequestContainerEnergySavingsIndicationLegacy(v s28.CellStateIndication) s28.SONtransferRequestContainer {
	return s28.SONtransferRequestContainer{
		Choice:                  s00.SONtransferRequestContainerChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferRequestContainerFailureEventReporting creates a SONtransferRequestContainer with the failureEventReporting alternative.
func BridgeNewSONtransferRequestContainerFailureEventReportingLegacy(v s24.FailureEventReport) s28.SONtransferRequestContainer {
	return s28.SONtransferRequestContainer{
		Choice:                s00.SONtransferRequestContainerChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// NewSONtransferResponseContainerCellLoadReporting creates a SONtransferResponseContainer with the cellLoadReporting alternative.
func BridgeNewSONtransferResponseContainerCellLoadReportingLegacy(v s21.CellLoadReportingResponse) s28.SONtransferResponseContainer {
	return s28.SONtransferResponseContainer{
		Choice:            s00.SONtransferResponseContainerChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferResponseContainerMultiCellLoadReporting creates a SONtransferResponseContainer with the multiCellLoadReporting alternative.
func BridgeNewSONtransferResponseContainerMultiCellLoadReportingLegacy(v s22.MultiCellLoadReportingResponse) s28.SONtransferResponseContainer {
	return s28.SONtransferResponseContainer{
		Choice:                 s00.SONtransferResponseContainerChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: v,
	}
}

// NewSONtransferResponseContainerEventTriggeredCellLoadReporting creates a SONtransferResponseContainer with the eventTriggeredCellLoadReporting alternative.
func BridgeNewSONtransferResponseContainerEventTriggeredCellLoadReportingLegacy(v s21.EventTriggeredCellLoadReportingResponse) s28.SONtransferResponseContainer {
	return s28.SONtransferResponseContainer{
		Choice:                          s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferResponseContainerHOReporting creates a SONtransferResponseContainer with the hOReporting alternative.
func BridgeNewSONtransferResponseContainerHOReportingLegacy(v struct{}) s28.SONtransferResponseContainer {
	return s28.SONtransferResponseContainer{
		Choice:      s00.SONtransferResponseContainerChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferResponseContainerEutranCellActivation creates a SONtransferResponseContainer with the eutranCellActivation alternative.
func BridgeNewSONtransferResponseContainerEutranCellActivationLegacy(v s25.CellActivationResponse) s28.SONtransferResponseContainer {
	return s28.SONtransferResponseContainer{
		Choice:               s00.SONtransferResponseContainerChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferResponseContainerEnergySavingsIndication creates a SONtransferResponseContainer with the energySavingsIndication alternative.
func BridgeNewSONtransferResponseContainerEnergySavingsIndicationLegacy(v struct{}) s28.SONtransferResponseContainer {
	return s28.SONtransferResponseContainer{
		Choice:                  s00.SONtransferResponseContainerChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferResponseContainerFailureEventReporting creates a SONtransferResponseContainer with the failureEventReporting alternative.
func BridgeNewSONtransferResponseContainerFailureEventReportingLegacy(v struct{}) s28.SONtransferResponseContainer {
	return s28.SONtransferResponseContainer{
		Choice:                s00.SONtransferResponseContainerChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// NewSONtransferCauseCellLoadReporting creates a SONtransferCause with the cellLoadReporting alternative.
func BridgeNewSONtransferCauseCellLoadReportingLegacy(v s00.CellLoadReportingCause) s24.SONtransferCause {
	return s24.SONtransferCause{
		Choice:            s00.SONtransferCauseChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferCauseMultiCellLoadReporting creates a SONtransferCause with the multiCellLoadReporting alternative.
func BridgeNewSONtransferCauseMultiCellLoadReportingLegacy(v s00.CellLoadReportingCause) s24.SONtransferCause {
	return s24.SONtransferCause{
		Choice:                 s00.SONtransferCauseChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: &v,
	}
}

// NewSONtransferCauseEventTriggeredCellLoadReporting creates a SONtransferCause with the eventTriggeredCellLoadReporting alternative.
func BridgeNewSONtransferCauseEventTriggeredCellLoadReportingLegacy(v s00.CellLoadReportingCause) s24.SONtransferCause {
	return s24.SONtransferCause{
		Choice:                          s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferCauseHOReporting creates a SONtransferCause with the hOReporting alternative.
func BridgeNewSONtransferCauseHOReportingLegacy(v s00.HOReportingCause) s24.SONtransferCause {
	return s24.SONtransferCause{
		Choice:      s00.SONtransferCauseChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferCauseEutranCellActivation creates a SONtransferCause with the eutranCellActivation alternative.
func BridgeNewSONtransferCauseEutranCellActivationLegacy(v s00.CellActivationCause) s24.SONtransferCause {
	return s24.SONtransferCause{
		Choice:               s00.SONtransferCauseChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferCauseEnergySavingsIndication creates a SONtransferCause with the energySavingsIndication alternative.
func BridgeNewSONtransferCauseEnergySavingsIndicationLegacy(v s00.CellStateIndicationCause) s24.SONtransferCause {
	return s24.SONtransferCause{
		Choice:                  s00.SONtransferCauseChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferCauseFailureEventReporting creates a SONtransferCause with the failureEventReporting alternative.
func BridgeNewSONtransferCauseFailureEventReportingLegacy(v s00.FailureEventReportingCause) s24.SONtransferCause {
	return s24.SONtransferCause{
		Choice:                s00.SONtransferCauseChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// NewCellLoadReportingResponseEUTRAN creates a CellLoadReportingResponse with the eUTRAN alternative.
func BridgeNewCellLoadReportingResponseEUTRANLegacy(v s21.EUTRANcellLoadReportingResponse) s21.CellLoadReportingResponse {
	return s21.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceEUTRAN,
		EUTRAN: &v,
	}
}

// NewCellLoadReportingResponseUTRAN creates a CellLoadReportingResponse with the uTRAN alternative.
func BridgeNewCellLoadReportingResponseUTRANLegacy(v []byte) s21.CellLoadReportingResponse {
	return s21.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceUTRAN,
		UTRAN:  v,
	}
}

// NewCellLoadReportingResponseGERAN creates a CellLoadReportingResponse with the gERAN alternative.
func BridgeNewCellLoadReportingResponseGERANLegacy(v []byte) s21.CellLoadReportingResponse {
	return s21.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceGERAN,
		GERAN:  v,
	}
}

// NewCellLoadReportingResponseEHRPD creates a CellLoadReportingResponse with the eHRPD alternative.
func BridgeNewCellLoadReportingResponseEHRPDLegacy(v s18.EHRPDSectorLoadReportingResponse) s21.CellLoadReportingResponse {
	return s21.CellLoadReportingResponse{
		Choice: s00.CellLoadReportingResponseChoiceEHRPD,
		EHRPD:  &v,
	}
}

// NewIRATCellIDEUTRAN creates a IRATCellID with the eUTRAN alternative.
func BridgeNewIRATCellIDEUTRANLegacy(v []byte) s21.IRATCellID {
	return s21.IRATCellID{
		Choice: s00.IRATCellIDChoiceEUTRAN,
		EUTRAN: v,
	}
}

// NewIRATCellIDUTRAN creates a IRATCellID with the uTRAN alternative.
func BridgeNewIRATCellIDUTRANLegacy(v []byte) s21.IRATCellID {
	return s21.IRATCellID{
		Choice: s00.IRATCellIDChoiceUTRAN,
		UTRAN:  v,
	}
}

// NewIRATCellIDGERAN creates a IRATCellID with the gERAN alternative.
func BridgeNewIRATCellIDGERANLegacy(v []byte) s21.IRATCellID {
	return s21.IRATCellID{
		Choice: s00.IRATCellIDChoiceGERAN,
		GERAN:  v,
	}
}

// NewIRATCellIDEHRPD creates a IRATCellID with the eHRPD alternative.
func BridgeNewIRATCellIDEHRPDLegacy(v s00.EHRPDSectorID) s21.IRATCellID {
	return s21.IRATCellID{
		Choice: s00.IRATCellIDChoiceEHRPD,
		EHRPD:  &v,
	}
}

// NewMultiCellLoadReportingResponseItemEUTRANResponse creates a MultiCellLoadReportingResponseItem with the eUTRANResponse alternative.
func BridgeNewMultiCellLoadReportingResponseItemEUTRANResponseLegacy(v s21.EUTRANResponse) s22.MultiCellLoadReportingResponseItem {
	return s22.MultiCellLoadReportingResponseItem{
		Choice:         s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse,
		EUTRANResponse: &v,
	}
}

// NewMultiCellLoadReportingResponseItemUTRANResponse creates a MultiCellLoadReportingResponseItem with the uTRANResponse alternative.
func BridgeNewMultiCellLoadReportingResponseItemUTRANResponseLegacy(v []byte) s22.MultiCellLoadReportingResponseItem {
	return s22.MultiCellLoadReportingResponseItem{
		Choice:        s00.MultiCellLoadReportingResponseItemChoiceUTRANResponse,
		UTRANResponse: v,
	}
}

// NewMultiCellLoadReportingResponseItemGERANResponse creates a MultiCellLoadReportingResponseItem with the gERANResponse alternative.
func BridgeNewMultiCellLoadReportingResponseItemGERANResponseLegacy(v []byte) s22.MultiCellLoadReportingResponseItem {
	return s22.MultiCellLoadReportingResponseItem{
		Choice:        s00.MultiCellLoadReportingResponseItemChoiceGERANResponse,
		GERANResponse: v,
	}
}

// NewMultiCellLoadReportingResponseItemEHRPD creates a MultiCellLoadReportingResponseItem with the eHRPD alternative.
func BridgeNewMultiCellLoadReportingResponseItemEHRPDLegacy(v s18.EHRPDMultiSectorLoadReportingResponseItem) s22.MultiCellLoadReportingResponseItem {
	return s22.MultiCellLoadReportingResponseItem{
		Choice: s00.MultiCellLoadReportingResponseItemChoiceEHRPD,
		EHRPD:  &v,
	}
}

// NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN creates a FailureEventReport with the tooEarlyInterRATHOReportFromEUTRAN alternative.
func BridgeNewFailureEventReportTooEarlyInterRATHOReportFromEUTRANLegacy(v s24.TooEarlyInterRATHOReportReportFromEUTRAN) s24.FailureEventReport {
	return s24.FailureEventReport{
		Choice:                             s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN,
		TooEarlyInterRATHOReportFromEUTRAN: &v,
	}
}

// MarshalAPERRequestedCellListTo appends a RequestedCellList list to bb.
func BridgeMarshalAPERRequestedCellListTo(list s23.RequestedCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERRequestedCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s21.BridgeIRATCellIDMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERReportingCellListTo(list s23.ReportingCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERReportingCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s23.BridgeReportingCellListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERMultiCellLoadReportingResponseTo(list s22.MultiCellLoadReportingResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERMultiCellLoadReportingResponseListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s22.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCandidateCellListTo(list s21.CandidateCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCandidateCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s21.BridgeIRATCellIDMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCandidatePCIListTo(list s17.CandidatePCIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCandidatePCIListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCandidatePCIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERCellsToActivateListTo(list s17.CellsToActivateList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERCellsToActivateListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s17.BridgeCellsToActivateListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERActivatedCellsListTo(list s16.ActivatedCellsList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERActivatedCellsListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s16.BridgeActivatedCellsListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func BridgeMarshalAPERNotificationCellListTo(list s23.NotificationCellList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s25.BridgeAsn1cAPERNotificationCellListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s23.BridgeNotificationCellListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func NewSONtransferRequestContainerCellLoadReporting(v struct{}, options ...aper.BuildOption) (s28.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerCellLoadReporting")
	}
	value := BridgeNewSONtransferRequestContainerCellLoadReportingLegacy(v)
	if _, err := s28.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerCellLoadReporting")
}

// NewSONtransferRequestContainerMultiCellLoadReporting constructs a checked complete value.
func NewSONtransferRequestContainerMultiCellLoadReporting(v s28.MultiCellLoadReportingRequest, options ...aper.BuildOption) (s28.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerMultiCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerMultiCellLoadReporting")
	}
	value := BridgeNewSONtransferRequestContainerMultiCellLoadReportingLegacy(v)
	if _, err := s28.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerMultiCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerMultiCellLoadReporting")
}

// NewSONtransferRequestContainerEventTriggeredCellLoadReporting constructs a checked complete value.
func NewSONtransferRequestContainerEventTriggeredCellLoadReporting(v s21.EventTriggeredCellLoadReportingRequest, options ...aper.BuildOption) (s28.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEventTriggeredCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEventTriggeredCellLoadReporting")
	}
	value := BridgeNewSONtransferRequestContainerEventTriggeredCellLoadReportingLegacy(v)
	if _, err := s28.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEventTriggeredCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerEventTriggeredCellLoadReporting")
}

// NewSONtransferRequestContainerHOReporting constructs a checked complete value.
func NewSONtransferRequestContainerHOReporting(v s25.HOReport, options ...aper.BuildOption) (s28.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerHOReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerHOReporting")
	}
	value := BridgeNewSONtransferRequestContainerHOReportingLegacy(v)
	if _, err := s28.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerHOReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerHOReporting")
}

// NewSONtransferRequestContainerEutranCellActivation constructs a checked complete value.
func NewSONtransferRequestContainerEutranCellActivation(v s26.CellActivationRequest, options ...aper.BuildOption) (s28.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEutranCellActivation")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEutranCellActivation")
	}
	value := BridgeNewSONtransferRequestContainerEutranCellActivationLegacy(v)
	if _, err := s28.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEutranCellActivation")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerEutranCellActivation")
}

// NewSONtransferRequestContainerEnergySavingsIndication constructs a checked complete value.
func NewSONtransferRequestContainerEnergySavingsIndication(v s28.CellStateIndication, options ...aper.BuildOption) (s28.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEnergySavingsIndication")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEnergySavingsIndication")
	}
	value := BridgeNewSONtransferRequestContainerEnergySavingsIndicationLegacy(v)
	if _, err := s28.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerEnergySavingsIndication")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerEnergySavingsIndication")
}

// NewSONtransferRequestContainerFailureEventReporting constructs a checked complete value.
func NewSONtransferRequestContainerFailureEventReporting(v s24.FailureEventReport, options ...aper.BuildOption) (s28.SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerFailureEventReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerFailureEventReporting")
	}
	value := BridgeNewSONtransferRequestContainerFailureEventReportingLegacy(v)
	if _, err := s28.BridgeSONtransferRequestContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerFailureEventReporting")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerFailureEventReporting")
}

// NewSONtransferResponseContainerCellLoadReporting constructs a checked complete value.
func NewSONtransferResponseContainerCellLoadReporting(v s21.CellLoadReportingResponse, options ...aper.BuildOption) (s28.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerCellLoadReporting")
	}
	value := BridgeNewSONtransferResponseContainerCellLoadReportingLegacy(v)
	if _, err := s28.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerCellLoadReporting")
}

// NewSONtransferResponseContainerMultiCellLoadReporting constructs a checked complete value.
func NewSONtransferResponseContainerMultiCellLoadReporting(v s22.MultiCellLoadReportingResponse, options ...aper.BuildOption) (s28.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerMultiCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerMultiCellLoadReporting")
	}
	value := BridgeNewSONtransferResponseContainerMultiCellLoadReportingLegacy(v)
	if _, err := s28.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerMultiCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerMultiCellLoadReporting")
}

// NewSONtransferResponseContainerEventTriggeredCellLoadReporting constructs a checked complete value.
func NewSONtransferResponseContainerEventTriggeredCellLoadReporting(v s21.EventTriggeredCellLoadReportingResponse, options ...aper.BuildOption) (s28.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEventTriggeredCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEventTriggeredCellLoadReporting")
	}
	value := BridgeNewSONtransferResponseContainerEventTriggeredCellLoadReportingLegacy(v)
	if _, err := s28.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEventTriggeredCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerEventTriggeredCellLoadReporting")
}

// NewSONtransferResponseContainerHOReporting constructs a checked complete value.
func NewSONtransferResponseContainerHOReporting(v struct{}, options ...aper.BuildOption) (s28.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerHOReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerHOReporting")
	}
	value := BridgeNewSONtransferResponseContainerHOReportingLegacy(v)
	if _, err := s28.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerHOReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerHOReporting")
}

// NewSONtransferResponseContainerEutranCellActivation constructs a checked complete value.
func NewSONtransferResponseContainerEutranCellActivation(v s25.CellActivationResponse, options ...aper.BuildOption) (s28.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEutranCellActivation")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEutranCellActivation")
	}
	value := BridgeNewSONtransferResponseContainerEutranCellActivationLegacy(v)
	if _, err := s28.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEutranCellActivation")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerEutranCellActivation")
}

// NewSONtransferResponseContainerEnergySavingsIndication constructs a checked complete value.
func NewSONtransferResponseContainerEnergySavingsIndication(v struct{}, options ...aper.BuildOption) (s28.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEnergySavingsIndication")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEnergySavingsIndication")
	}
	value := BridgeNewSONtransferResponseContainerEnergySavingsIndicationLegacy(v)
	if _, err := s28.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerEnergySavingsIndication")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerEnergySavingsIndication")
}

// NewSONtransferResponseContainerFailureEventReporting constructs a checked complete value.
func NewSONtransferResponseContainerFailureEventReporting(v struct{}, options ...aper.BuildOption) (s28.SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerFailureEventReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerFailureEventReporting")
	}
	value := BridgeNewSONtransferResponseContainerFailureEventReportingLegacy(v)
	if _, err := s28.BridgeSONtransferResponseContainerMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s28.SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerFailureEventReporting")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerFailureEventReporting")
}

// NewSONtransferCauseCellLoadReporting constructs a checked complete value.
func NewSONtransferCauseCellLoadReporting(v s00.CellLoadReportingCause, options ...aper.BuildOption) (s24.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseCellLoadReporting")
	}
	value := BridgeNewSONtransferCauseCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseCellLoadReporting")
}

// NewSONtransferCauseMultiCellLoadReporting constructs a checked complete value.
func NewSONtransferCauseMultiCellLoadReporting(v s00.CellLoadReportingCause, options ...aper.BuildOption) (s24.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseMultiCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseMultiCellLoadReporting")
	}
	value := BridgeNewSONtransferCauseMultiCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseMultiCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseMultiCellLoadReporting")
}

// NewSONtransferCauseEventTriggeredCellLoadReporting constructs a checked complete value.
func NewSONtransferCauseEventTriggeredCellLoadReporting(v s00.CellLoadReportingCause, options ...aper.BuildOption) (s24.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEventTriggeredCellLoadReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEventTriggeredCellLoadReporting")
	}
	value := BridgeNewSONtransferCauseEventTriggeredCellLoadReportingLegacy(v)
	if _, err := s24.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEventTriggeredCellLoadReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseEventTriggeredCellLoadReporting")
}

// NewSONtransferCauseHOReporting constructs a checked complete value.
func NewSONtransferCauseHOReporting(v s00.HOReportingCause, options ...aper.BuildOption) (s24.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseHOReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseHOReporting")
	}
	value := BridgeNewSONtransferCauseHOReportingLegacy(v)
	if _, err := s24.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseHOReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseHOReporting")
}

// NewSONtransferCauseEutranCellActivation constructs a checked complete value.
func NewSONtransferCauseEutranCellActivation(v s00.CellActivationCause, options ...aper.BuildOption) (s24.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEutranCellActivation")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEutranCellActivation")
	}
	value := BridgeNewSONtransferCauseEutranCellActivationLegacy(v)
	if _, err := s24.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEutranCellActivation")
	}
	return value, aper.OperationError(nil, "SONtransferCauseEutranCellActivation")
}

// NewSONtransferCauseEnergySavingsIndication constructs a checked complete value.
func NewSONtransferCauseEnergySavingsIndication(v s00.CellStateIndicationCause, options ...aper.BuildOption) (s24.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEnergySavingsIndication")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEnergySavingsIndication")
	}
	value := BridgeNewSONtransferCauseEnergySavingsIndicationLegacy(v)
	if _, err := s24.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseEnergySavingsIndication")
	}
	return value, aper.OperationError(nil, "SONtransferCauseEnergySavingsIndication")
}

// NewSONtransferCauseFailureEventReporting constructs a checked complete value.
func NewSONtransferCauseFailureEventReporting(v s00.FailureEventReportingCause, options ...aper.BuildOption) (s24.SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseFailureEventReporting")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseFailureEventReporting")
	}
	value := BridgeNewSONtransferCauseFailureEventReportingLegacy(v)
	if _, err := s24.BridgeSONtransferCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.SONtransferCause{}, aper.OperationError(err, "SONtransferCauseFailureEventReporting")
	}
	return value, aper.OperationError(nil, "SONtransferCauseFailureEventReporting")
}

// NewCellLoadReportingResponseEUTRAN constructs a checked complete value.
func NewCellLoadReportingResponseEUTRAN(v s21.EUTRANcellLoadReportingResponse, options ...aper.BuildOption) (s21.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	value := BridgeNewCellLoadReportingResponseEUTRANLegacy(v)
	if _, err := s21.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEUTRAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseEUTRAN")
}

// NewCellLoadReportingResponseUTRAN constructs a checked complete value.
func NewCellLoadReportingResponseUTRAN(v []byte, options ...aper.BuildOption) (s21.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	value := BridgeNewCellLoadReportingResponseUTRANLegacy(v)
	if _, err := s21.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUTRAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseUTRAN")
}

// NewCellLoadReportingResponseGERAN constructs a checked complete value.
func NewCellLoadReportingResponseGERAN(v []byte, options ...aper.BuildOption) (s21.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	value := BridgeNewCellLoadReportingResponseGERANLegacy(v)
	if _, err := s21.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseGERAN")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseGERAN")
}

// NewCellLoadReportingResponseEHRPD constructs a checked complete value.
func NewCellLoadReportingResponseEHRPD(v s18.EHRPDSectorLoadReportingResponse, options ...aper.BuildOption) (s21.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
	}
	value := BridgeNewCellLoadReportingResponseEHRPDLegacy(v)
	if _, err := s21.BridgeCellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseEHRPD")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseEHRPD")
}

// NewIRATCellIDEUTRAN constructs a checked complete value.
func NewIRATCellIDEUTRAN(v []byte, options ...aper.BuildOption) (s21.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDEUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDEUTRAN")
	}
	value := BridgeNewIRATCellIDEUTRANLegacy(v)
	if _, err := s21.BridgeIRATCellIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDEUTRAN")
	}
	return value, aper.OperationError(nil, "IRATCellIDEUTRAN")
}

// NewIRATCellIDUTRAN constructs a checked complete value.
func NewIRATCellIDUTRAN(v []byte, options ...aper.BuildOption) (s21.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDUTRAN")
	}
	value := BridgeNewIRATCellIDUTRANLegacy(v)
	if _, err := s21.BridgeIRATCellIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDUTRAN")
	}
	return value, aper.OperationError(nil, "IRATCellIDUTRAN")
}

// NewIRATCellIDGERAN constructs a checked complete value.
func NewIRATCellIDGERAN(v []byte, options ...aper.BuildOption) (s21.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDGERAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDGERAN")
	}
	value := BridgeNewIRATCellIDGERANLegacy(v)
	if _, err := s21.BridgeIRATCellIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDGERAN")
	}
	return value, aper.OperationError(nil, "IRATCellIDGERAN")
}

// NewIRATCellIDEHRPD constructs a checked complete value.
func NewIRATCellIDEHRPD(v s00.EHRPDSectorID, options ...aper.BuildOption) (s21.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDEHRPD")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDEHRPD")
	}
	value := BridgeNewIRATCellIDEHRPDLegacy(v)
	if _, err := s21.BridgeIRATCellIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s21.IRATCellID{}, aper.OperationError(err, "IRATCellIDEHRPD")
	}
	return value, aper.OperationError(nil, "IRATCellIDEHRPD")
}

// NewMultiCellLoadReportingResponseItemEUTRANResponse constructs a checked complete value.
func NewMultiCellLoadReportingResponseItemEUTRANResponse(v s21.EUTRANResponse, options ...aper.BuildOption) (s22.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEUTRANResponse")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEUTRANResponse")
	}
	value := BridgeNewMultiCellLoadReportingResponseItemEUTRANResponseLegacy(v)
	if _, err := s22.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEUTRANResponse")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemEUTRANResponse")
}

// NewMultiCellLoadReportingResponseItemUTRANResponse constructs a checked complete value.
func NewMultiCellLoadReportingResponseItemUTRANResponse(v []byte, options ...aper.BuildOption) (s22.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUTRANResponse")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUTRANResponse")
	}
	value := BridgeNewMultiCellLoadReportingResponseItemUTRANResponseLegacy(v)
	if _, err := s22.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUTRANResponse")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemUTRANResponse")
}

// NewMultiCellLoadReportingResponseItemGERANResponse constructs a checked complete value.
func NewMultiCellLoadReportingResponseItemGERANResponse(v []byte, options ...aper.BuildOption) (s22.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemGERANResponse")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemGERANResponse")
	}
	value := BridgeNewMultiCellLoadReportingResponseItemGERANResponseLegacy(v)
	if _, err := s22.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemGERANResponse")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemGERANResponse")
}

// NewMultiCellLoadReportingResponseItemEHRPD constructs a checked complete value.
func NewMultiCellLoadReportingResponseItemEHRPD(v s18.EHRPDMultiSectorLoadReportingResponseItem, options ...aper.BuildOption) (s22.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEHRPD")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEHRPD")
	}
	value := BridgeNewMultiCellLoadReportingResponseItemEHRPDLegacy(v)
	if _, err := s22.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s22.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemEHRPD")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemEHRPD")
}

// NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN constructs a checked complete value.
func NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN(v s24.TooEarlyInterRATHOReportReportFromEUTRAN, options ...aper.BuildOption) (s24.FailureEventReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s24.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
	}
	value := BridgeNewFailureEventReportTooEarlyInterRATHOReportFromEUTRANLegacy(v)
	if _, err := s24.BridgeFailureEventReportMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s24.FailureEventReport{}, aper.OperationError(err, "FailureEventReportTooEarlyInterRATHOReportFromEUTRAN")
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

// RecommendedCellItemCodec binds the complete APER value type.
func RecommendedCellItemCodec() RecommendedCellItemValueCodec {
	return RecommendedCellItemIEs().RecommendedCellItem().Codec()
}
func BridgeMergeNestedValidation(dst *s25.ValidationReport, src s25.ValidationReport) {
	if *s25.BridgeValidationReportFieldErr(dst) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(&src) != nil {
		*s25.BridgeValidationReportFieldErr(dst) = *s25.BridgeValidationReportFieldErr(&src)
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(dst))
	var err error
	dst.Issues, err = aper.AppendValues(bb, dst.Issues, src.Issues...)
	if err != nil {
		*s25.BridgeValidationReportFieldErr(dst) = err
		return
	}
	dst.Deferred, err = aper.AppendValues(bb, dst.Deferred, src.Deferred...)
	if err != nil {
		*s25.BridgeValidationReportFieldErr(dst) = err
		return
	}
	dst.Unchecked, err = aper.AppendValues(bb, dst.Unchecked, src.Unchecked...)
	if err != nil {
		*s25.BridgeValidationReportFieldErr(dst) = err
		return
	}
	if !src.Complete {
		dst.Complete = false
	}
}
func BridgeInitialContextSetupFailureFieldPerPadding(v *InitialContextSetupFailure) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeInitialContextSetupFailureMethodMarshalAPERBudget(v *InitialContextSetupFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInitialContextSetupFailureMethodUnmarshalAPERFrom(v *InitialContextSetupFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeLocationReportingFailureIndicationFieldPerPadding(v *LocationReportingFailureIndication) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeLocationReportingFailureIndicationMethodMarshalAPERBudget(v *LocationReportingFailureIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLocationReportingFailureIndicationMethodUnmarshalAPERFrom(v *LocationReportingFailureIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeMMEConfigurationUpdateAcknowledgeFieldPerPadding(v *MMEConfigurationUpdateAcknowledge) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v *MMEConfigurationUpdateAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEConfigurationUpdateAcknowledgeMethodUnmarshalAPERFrom(v *MMEConfigurationUpdateAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeMMEConfigurationUpdateFailureFieldPerPadding(v *MMEConfigurationUpdateFailure) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(v *MMEConfigurationUpdateFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEConfigurationUpdateFailureMethodUnmarshalAPERFrom(v *MMEConfigurationUpdateFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeMMEStatusTransferFieldPerPadding(v *MMEStatusTransfer) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeMMEStatusTransferMethodMarshalAPERBudget(v *MMEStatusTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEStatusTransferMethodUnmarshalAPERFrom(v *MMEStatusTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeNASNonDeliveryIndicationFieldPerPadding(v *NASNonDeliveryIndication) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeNASNonDeliveryIndicationMethodMarshalAPERBudget(v *NASNonDeliveryIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNASNonDeliveryIndicationMethodUnmarshalAPERFrom(v *NASNonDeliveryIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgePathSwitchRequestFailureFieldPerPadding(v *PathSwitchRequestFailure) *aper.FinalPadding {
	return &v.perPadding
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
func BridgePathSwitchRequestFailureMethodMarshalAPERBudget(v *PathSwitchRequestFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePathSwitchRequestFailureMethodUnmarshalAPERFrom(v *PathSwitchRequestFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgePrivateMessageFieldPerPadding(v *PrivateMessage) *aper.FinalPadding { return &v.perPadding }
func BridgePrivateMessageFieldReceived(v *PrivateMessage) *bool                { return &v.received }
func BridgePrivateMessageFieldReceivedAbsolute(v *PrivateMessage) *bool        { return &v.receivedAbsolute }
func BridgePrivateMessageFieldReceivedBytes(v *PrivateMessage) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePrivateMessageFieldReceivedLocation(v *PrivateMessage) *aper.Location {
	return &v.receivedLocation
}
func BridgePrivateMessageMethodMarshalAPERBudget(v *PrivateMessage, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePrivateMessageMethodUnmarshalAPERFrom(v *PrivateMessage, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeRecommendedCellItemIEContainerValueCodecFieldDecode(v *RecommendedCellItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellItemIEContainer, error) {
	return &v.decode
}
func BridgeRecommendedCellItemIEContainerValueCodecFieldEncode(v *RecommendedCellItemIEContainerValueCodec) *func(RecommendedCellItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellItemIEFieldMethodUnmarshalAPERFrom(v *RecommendedCellItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeRecommendedCellItemIEValueFieldId(v *RecommendedCellItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeRecommendedCellItemIEValueFieldIsOpaque(v *RecommendedCellItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeRecommendedCellItemIEValueFieldOpaque(v *RecommendedCellItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeRecommendedCellItemIEValueFieldRowRecommendedCellItem(v *RecommendedCellItemIEValue) **RecommendedCellItem {
	return &v.rowRecommendedCellItem
}
func BridgeRecommendedCellItemIEValueMethodMatchesID(v RecommendedCellItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeRecommendedCellItemIEValueMethodRule(v RecommendedCellItemIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeRecommendedCellsForPagingFieldReceived(v *RecommendedCellsForPaging) *bool {
	return &v.received
}
func BridgeRecommendedCellsForPagingFieldReceivedAbsolute(v *RecommendedCellsForPaging) *bool {
	return &v.receivedAbsolute
}
func BridgeRecommendedCellsForPagingFieldReceivedBytes(v *RecommendedCellsForPaging) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERBudget(v *RecommendedCellsForPaging, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRecommendedCellsForPagingMethodMarshalAPERTo(v *RecommendedCellsForPaging, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedCellsForPagingMethodUnmarshalAPERFrom(v *RecommendedCellsForPaging, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedCellsForPagingMethodUnmarshalAPERWithOptions(v *RecommendedCellsForPaging, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
